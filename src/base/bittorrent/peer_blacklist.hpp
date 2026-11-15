#pragma once

#include <algorithm>
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <libtorrent/torrent_info.hpp>

#include <QHostAddress>
#include <QString>

#include "base/net/geoipmanager.h"

#include "peer_filter_plugin.hpp"

// The filters below are inline functions with external linkage, so the helpers
// they call must have external linkage as well: referencing an entity of an
// unnamed namespace from an inline function is an ODR violation
// ([basic.def.odr]). A named namespace keeps a single set of inline helpers
// shared by every translation unit including this header, and it also lets the
// unit tests exercise them directly.
namespace PeerFilterDetail
{
  // All the signatures checked below are plain ASCII, so the locale aware and
  // allocation heavy std::regex machinery can be replaced by the helpers in
  // this namespace. They run for every peer that connects (and for a number of
  // peer events afterwards), therefore they are allocation free and keep the
  // number of passes over the input as low as possible.

  constexpr char ascii_to_lower(const char c)
  {
    return ((c >= 'A') && (c <= 'Z')) ? static_cast<char>(c + ('a' - 'A')) : c;
  }

  // case insensitive (ASCII only) substring search
  inline bool contains_ascii_ci(const std::string_view haystack, const std::string_view needle)
  {
    if (needle.empty() || (haystack.size() < needle.size()))
      return false;

    const auto equals_ci = [](const char lhs, const char rhs)
    {
      return ascii_to_lower(lhs) == ascii_to_lower(rhs);
    };
    return std::search(haystack.cbegin(), haystack.cend()
                       , needle.cbegin(), needle.cend(), equals_ci) != haystack.cend();
  }

  template <typename Needles>
  bool contains_any_ascii_ci(const std::string_view haystack, const Needles &needles)
  {
    return std::any_of(needles.cbegin(), needles.cend(), [haystack](const std::string_view needle)
    {
      return contains_ascii_ci(haystack, needle);
    });
  }

  // first 8 bytes of the peer id, which is all the client tags below look at
  inline std::string_view peer_id_tag(const lt::peer_info &info)
  {
    return {info.pid.data(), 8};
  }

  // "-LT1220-" / "-LT2070-": fake libtorrent builds used by offline downloaders
  inline bool is_fake_libtorrent_id(const std::string_view peer_id)
  {
    return (peer_id == "-LT1220-") || (peer_id == "-LT2070-");
  }

  // "-(XL|SD|XF|QD|BN|DL|TS|DT|HP|XG|XX)\d+-" matched against the first 8 bytes
  // of the peer id. The match has to cover all 8 bytes, so "\d+" is always
  // exactly 4 digits, i.e. the client id is "-XXdddd-".
  inline bool is_banned_peer_id(const std::string_view peer_id)
  {
    static constexpr std::array<std::string_view, 11> banned_client_ids {
      "XL", "SD", "XF", "QD", "BN", "DL", "TS", "DT", "HP", "XG", "XX"
    };

    if ((peer_id.size() != 8) || (peer_id.front() != '-') || (peer_id.back() != '-'))
      return false;

    if (std::find(banned_client_ids.cbegin(), banned_client_ids.cend(), peer_id.substr(1, 2)) == banned_client_ids.cend())
      return false;

    return std::all_of((peer_id.cbegin() + 3), (peer_id.cbegin() + 7), [](const char c)
    {
      return (c >= '0') && (c <= '9');
    });
  }

  constexpr bool is_ascii_word(const char c)
  {
    return ((c >= '0') && (c <= '9')) || ((c >= 'A') && (c <= 'Z'))
        || ((c >= 'a') && (c <= 'z')) || (c == '_');
  }

  // "-(UW\w{4}|SP([0-2]\d{3}|3[0-5]\d{2}))-" matched against the first 8 bytes
  // of the peer id, i.e. "-UWxxxx-" or "-SPdddd-" (the latter being a build
  // number in the range 0000...3599).
  inline bool is_media_player_id(const std::string_view peer_id)
  {
    if ((peer_id.size() != 8) || (peer_id.front() != '-') || (peer_id.back() != '-'))
      return false;

    const std::string_view client_id = peer_id.substr(1, 2);
    const std::string_view build = peer_id.substr(3, 4);

    if (client_id == "UW")
      return std::all_of(build.cbegin(), build.cend(), is_ascii_word);

    if (client_id != "SP")
      return false;

    int build_number = 0;
    for (const char c : build)
    {
      if ((c < '0') || (c > '9'))
        return false;

      build_number = (build_number * 10) + (c - '0');
    }
    return build_number <= 3599;
  }

  // A GeoIP lookup is much more expensive than any of the string checks above,
  // so it is only performed once a peer already looks suspicious. Note that the
  // lookup returns an empty string when the database is unavailable, which
  // never matches a country below.
  inline QString lookup_peer_country(const lt::peer_info &info)
  {
    const Net::GeoIPManager *const geoIPManager = Net::GeoIPManager::instance();
    if (!geoIPManager)
      return {};

    return geoIPManager->lookup(QHostAddress(info.ip.data()));
  }
}

// bad peer filter
inline bool is_bad_peer(const lt::peer_info &info)
{
  // 极强封禁名单: 国际通用，不再限定国家/地区（宁错杀不放过）。
  // PCDN / 离线 / 吸血客户端通用签名（任何地区一律封禁）。
  // "thunder" also covers "Thunder X"/"ThunderX", "pcdn" covers "cdn-pcdn",
  // and "gotcha" covers "gotcha+torrent".
  static constexpr std::array<std::string_view, 15> banned_clients {
    "dt/torrent", "hp/torrent", "xm/torrent", "dl/torrent", "x/torrent", "sn/torrent"
    , "gopeed dev", "rain 0.0.0", "taipei-torrent", "xunlei", "thunder", "pcdn"
    , "cdndownload", "magnetdl", "emule"
  };
  static constexpr std::array<std::string_view, 4> banned_user_agents {
    "cacao_torrent", "gotcha", "torrentsearcher", "web.torrent"
  };

  const std::string_view client = info.client;

  // plain substring match: O(n), much cheaper than a std::regex_search
  // 针对疑似 PCDN 伪装的 qBittorrent 4.6.7 构建号
  if (client.find("qBittorrent/4.6.7") != std::string_view::npos)
    return true;

  // 吸血 / PCDN 签名 —— 全球封禁
  if (PeerFilterDetail::contains_any_ascii_ci(client, banned_clients)
      || PeerFilterDetail::contains_any_ascii_ci(client, banned_user_agents))
  {
    return true;
  }

  return PeerFilterDetail::is_banned_peer_id(PeerFilterDetail::peer_id_tag(info));
}

// Unknown Peer filter
inline bool is_unknown_peer(const lt::peer_info &info)
{
  // cheap test first: only peers with an unknown client are worth a GeoIP lookup
  if (info.client.find("Unknown") == std::string::npos)
    return false;

  return PeerFilterDetail::lookup_peer_country(info) == QLatin1String("CN");
}

// Offline Downloader filter
inline bool is_offline_downloader(const lt::peer_info &info)
{
  // 115: Old data, may out of date.
  const bool maybe_fake_transmission = (info.ip.port() >= 65000)
      && (info.client.find("Transmission") != std::string::npos);

  // PikPak: PikPak is renting Worldstream server and announce as LT1220/LT2070, the best way is block the ip range via ip filter(?)
  // Xunlei: it seems Xunlei is using LT2070 too
  const bool maybe_fake_libtorrent = PeerFilterDetail::is_fake_libtorrent_id(
      PeerFilterDetail::peer_id_tag(info));

  if (!maybe_fake_transmission && !maybe_fake_libtorrent)
    return false;

  // both signatures are country specific, so the GeoIP database is queried last
  const QString country = PeerFilterDetail::lookup_peer_country(info);
  if (country.isEmpty())
    return false;

  return (maybe_fake_transmission && (country == QLatin1String("CN")))
      || (maybe_fake_libtorrent && ((country == QLatin1String("NL")) || (country == QLatin1String("CN"))));
}

// BitTorrent Media Player Peer filter
inline bool is_bittorrent_media_player(const lt::peer_info &info)
{
  if ((info.client.find("StellarPlayer") != std::string::npos)
      || (info.client.find("Elementum") != std::string::npos))
  {
    return true;
  }

  return PeerFilterDetail::is_media_player_id(PeerFilterDetail::peer_id_tag(info));
}


// drop connection action
inline void drop_connection(lt::peer_connection_handle ph)
{
  ph.disconnect(boost::asio::error::connection_refused, lt::operation_t::bittorrent, lt::disconnect_severity_t{0});
}


template <typename F>
auto wrap_filter(F filter)
{
  return [filter = std::move(filter)](const lt::peer_info &info, const bool handshake, bool *stop_filtering)
  {
    const bool matched = filter(info);
    *stop_filtering = !handshake && !matched;
    return matched;
  };
}


inline std::shared_ptr<lt::torrent_plugin> create_peer_action_plugin(
    const lt::torrent_handle &th,
    filter_function filter,
    action_function action)
{
  // ignore private torrents
  const auto torrentInfo = th.torrent_file();
  if (torrentInfo && torrentInfo->priv())
    return nullptr;

  return std::make_shared<peer_action_plugin>(std::move(filter), std::move(action));
}


// plugins factory functions

inline std::shared_ptr<lt::torrent_plugin> create_drop_bad_peers_plugin(lt::torrent_handle const &th, client_data)
{
  return create_peer_action_plugin(th, wrap_filter(is_bad_peer), drop_connection);
}

inline std::shared_ptr<lt::torrent_plugin> create_drop_unknown_peers_plugin(lt::torrent_handle const &th, client_data)
{
  return create_peer_action_plugin(th, wrap_filter(is_unknown_peer), drop_connection);
}

inline std::shared_ptr<lt::torrent_plugin> create_drop_offline_downloader_plugin(lt::torrent_handle const &th, client_data)
{
  return create_peer_action_plugin(th, wrap_filter(is_offline_downloader), drop_connection);
}

inline std::shared_ptr<lt::torrent_plugin> create_drop_bittorrent_media_player_plugin(lt::torrent_handle const &th, client_data)
{
  return create_peer_action_plugin(th, wrap_filter(is_bittorrent_media_player), drop_connection);
}
