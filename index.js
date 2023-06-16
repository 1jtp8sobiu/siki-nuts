
/**
  * Sikiのスレッドや板を読んだり投稿する際の通信を編集します 
  * フォルダをpluginsへ配置して有効化
  * fsやcrypto等のnodeの標準モジュールを requireすることが出来ます
  * 
  * @version 0.0.3
 */

/**
 * 設定を同じ場所にあるconfig.jsonから読み取ります
 * @type {Object<string, string|number|boolean>}}
 */
const settings = require('./config')

const { createHmac } = require('crypto')
const fs = require('fs')

const DAT_AUTH_URL = 'https://api.5ch.net/v1/auth/'
const DAT_API_URL = 'https://api.5ch.net'

const DAT_FILTER_REGEXP = /^https?:\/\/(?<server>\w+\.(?:5ch\.net|bbspink\.com))\/(?<board>\w+)\/dat\/(?<key>\d+)\.dat$/
const POSTAPI_FILTER_REGEXP = /^https?:\/\/(?<server>\w+\.(?:5ch\.net))\/test\/bbs\.cgi/

const DEVICE_OS = {
  'JaneStyle': ['Windows'],
  'Live5ch': ['Windows'],
  'BathyScaphe': ['Mac'],
  'V2C-R': ['Windows', 'Mac', 'Linux'],
  '2chMate': ['Android'],
  'Ciisaa': ['Android'],
  '2chGear': ['Android'],
  'En2ch': ['Android'],
  'JaneStyle_Android': ['Android'],
  'JaneStyle_iOS': ['iOS'],
  'BB2C': ['iOS'],
  'Twinkle': ['iOS']
}

const BBSPINK_SERVER = new Set(['mercury', 'phoebe'])

let server_lock = {}

// ワークスペース毎の設定
let workspace_settings = {}

  ; (async () => {
    try {
      for (let filename of await fs.promises.readdir(__dirname)) {
        let [, d] = filename.match(/workspace(\d+)\.json$/) || []
        if (d >= 0) {
          workspace_settings[d] = require(`./workspace${d}`)
        }
      }
    } catch (e) {
      console.log(e)
    }
  })();


/**
 * @typedef {Object} Conf - request_hook_conf.jsへデータを保存します 
 * @property {(key: string) => string} get - 保存したデータの読み込み
 * @property {(key: string, value: string) => string} set - 任意のデータを保存
 * @property {(key: string) => string} delete - データの削除
 */

/**
 * @callback SimpleFetch - 通信を行います
 * @param {string} url
 * @param {{ [key: string]: string }} headers - リクエストヘッダ
 * @param {"GET" | "POST" | "HEAD" | "PUT" | "DELETE"} method - HTTP リクエストメソッド
 * @param {string} body - エンコードされたクエリストリング
 * @param {string} encoding - 通信先の文字エンコーディングを必要に応じて指定(指定しない場合自動で推測されます)
 * @return {Promise<{headers:{ [key: string]: string }, body: string}>}
 */

/**
 * @typedef {Object} Log - ログを残します
 * @property {(message: string) => void } error - ログを残す(errorレベル) 
 * @property {(message: string) => void } warn - ログを残す(warnレベル) 
 * @property {(message: string) => void } info - ログを残す(infoレベル) 
 * @property {(message: string) => void } verbose - ログを残す(verboseレベル) 
 * @property {(message: string) => void } debug - ログを残す(debugレベル) 
 */

/**
 * URLリクエスト前のヘッダやパラメータを変更します。
 * 
 * @param {Object} tools - データの保存などで利用できるツール
 * @param {Conf} tools.conf
 * @param {SimpleFetch} tools.simplefetch
 * @param {Log} tools.log
 * @param {{ [key: string]: string }} tools.siki_values - workspaceidやuser_dir,log_dir等の値が入っています
 * @param {string} url - リクエストされるURL
 * @param {"GET" | "POST" | "HEAD" | "PUT" | "DELETE"} method - HTTP リクエストメソッド
 * @param {{ [key: string]: string }} headers - リクエストされるhttpヘッダー 全て小文字となります
 * @param {string} payload - 本来リクエストされるクエリストリング aa=bb&cc=dd&ee= ... という形式でパーセントエンコード済み
 * @param {{ [key: string]: string }} query - リクエストされるクエリー エンコードはされていません
 * @return {{url?: string, headers?: { [key: string]: string }, payload?: string, method?: string}} - URLのリクエストパラメータ 返さない場合は本来の内容で処理が進みます
 * 
 * @example - 特定のサイトへのアクセスの場合にUser Agentを変更しクエリストリングを変更
 * const beforeRequest = async (tools, url, method, headers, payload, query) => {
 *   if(url.match(/example\.com/)) {
 *     headers['user-agent'] = 'NCSA_Mosaic/2.0 (Windows 3.1)'
 *     payload = 'a=1&b=%E3%81%82'
 *   }
 *   return { headers, payload }
 * }
 */
module.exports.beforeRequest = async (tools, url, method, headers, payload, query) => {
  const { conf, simplefetch, log, siki_values } = tools
  // 処理を記述
  try {
    const s = settings_get(siki_values.workspaceid)
    if (s.API_DAT) {
      const dat_m = url.match(DAT_FILTER_REGEXP)
      if (dat_m && dat_m.groups.key) {
        let { server, board, key } = dat_m.groups
        let sid = conf.get(s.workspaceid >= 0 ? `${s.workspaceid}.sid` : "sid")
        if (!sid) {
          log.info("dat sid updated.")
          let ua = s.DAT_USER_AGENT || headers['user-agent']
          const auth = dat_authenticate(ua, s)
          let { body } = await simplefetch(auth.url, auth.headers, 'POST', auth.body)
          if (body) {
            sid = body.split(':')[1]
            if (sid) {
              conf.set(s.workspaceid >= 0 ? `${s.workspaceid}.sid` : "sid", sid)
            } else {
              log.error("dat authenticate error.")
              return { url, headers, payload, method }
            }
          }
        }
        if (headers['range']) {
          headers = {
            'range': headers.range
          }
        } else {
          headers = {}
        }
        if (sid) {
          s.DEBUG && log.info(`GETDAT ${url}`)
          return get_dat({ server, board, key }, headers, sid, s)
        }
      }
    }
    if (s.API_POST) {
      const post_m = url.match(POSTAPI_FILTER_REGEXP)
      if (post_m) {
        let { server, board, key } = post_m.groups
        return post_by_api({ server, board, key }, headers, payload, query, tools, s)
      }
    }

  } catch (e) {
    throw e
  }

  return { url, headers, payload, method }
}


/**
 * 
 * 
 * @module afterRequest URLリクエスト後のヘッダや内容を変更します。
 * @param {Object} tools - データの保存などで利用できるツール
 * @param {Conf} tools.conf
 * @param {SimpleFetch} tools.simplefetch
 * @param {Log} tools.log
 * @param {{ [key: string]: string }} tools.siki_values - workspaceidやuser_dir,log_dir等の値が入っています
 * @param {string} url - リクエストされたURL
 * @param {number} statusCode - HTTPステータスコード
 * @param {{ [key: string]: string }} response_headers - サーバーから帰って来たhttpヘッダー 全て小文字となります
 * @param {string} response_body - 受け取ったレスポンス内容 レスポンスのエンコーディングに関係なくユニコードに変換済み
 * @return {{statusCode?: number, response_headers?: { [key: string]: string }, response_body?: string}} - レスポンスヘッダと内容を返してください 返さない場合は本来の内容で処理が進みます
 * 
 * @example - 受け取った内容からストレージへ保存
 * const afterRequest = async (tools, url, response_headers, response_body) => {
 *   const { conf } = tools
 *   if(url.match(/example\.com/)) {
 *     conf.set('x', response_body)
 *   }
 *   return { response_headers, response_body }
 * }
 */
module.exports.afterRequest = async (tools, url, statusCode, response_headers, response_body) => {
  const { conf, simplefetch, log, siki_values } = tools
  // 処理を記述

  try {
    const s = settings_get(siki_values.workspaceid)
    if (s.API_DAT) {
      if (url.match(/^https:\/\/api\.5ch\.net/)) {
        let length = parseInt(response_headers['content-length'])
        if (response_body?.match(/^ng.*/) && length < 30) {
          conf.delete(s.workspaceid >= 0 ? `${s.workspaceid}.sid` : "sid")
          log.warn(response_body)
        }
        switch (response_headers['thread-status']) {
          case '1':
            if (length > 0) {
              if (
                length > 2 && !response_body.match(/<>/) ||
                (statusCode !== 200 && statusCode !== 206 && statusCode !== 304)
              ) {
                log.info("delete old sid")
                conf.delete(s.workspaceid >= 0 ? `${s.workspaceid}.sid` : "sid")
              }
              if (statusCode == 206 && length == 1) {
                statusCode = 304
                response_body = ''
              }
            }
            break
          default:
            // kako
            let now = new Date().getTime()
            let [, sv, bd, ky] = url.match(/\/(\w+)\/(\w+)\/(\d+)$/) || []
            if (ky) {
              let rsv = BBSPINK_SERVER.has(sv) ? `${sv}.bbspink.com` : `${sv}.5ch.net`
              let read_url = `https://${rsv}/test/read\.cgi/${bd}/${ky}/`
              if (now - server_lock[rsv] < (s.SAME_SERVER_WAIT || 3000)) { // gone. 対策
                return
              } else {
                s.DEBUG && log.info(`READ: ${read_url}`)
                server_lock[rsv] = now
                let { headers, body } = await simplefetch(read_url, {}, "GET")
                let { dat } = parse_read_cgi(headers, body) || {}
                if (dat) {
                  return { statusCode: 200, response_headers, response_body: dat }
                }
              }
            }
        }
        return { statusCode, response_headers, response_body }
      }
    }
    if (s.API_POST) {
      const bbs_m = url.match(POSTAPI_FILTER_REGEXP)
      if (bbs_m && bbs_m.groups.server) {
        if (response_headers['x-chx-error']) {
          let chx_error = response_headers['x-chx-error']
          s.DEBUG && log.warn('ERROR: ' + chx_error)
          if (chx_error.match(/^E\d+/)) {
            log.info('Delete MonaKey ' + chx_error)
            conf.delete(s.workspaceid >= 0 ? `${s.workspaceid}.MonaKey` : "MonaKey")
          }
        }
        if (response_headers['x-monakey']) {
          conf.set(s.workspaceid >= 0 ? `${s.workspaceid}.MonaKey` : "MonaKey", response_headers['x-monakey'])
          // 取得直後は多分書けないので waitをかける
          await new Promise(r => setTimeout(r, 2000))
        }
        if (response_headers['x-ronin-stat']) {
          if (response_headers['x-ronin-stat'].match(/^NG/)) {
            log.warn(response_headers['x-ronin-stat'])
            conf.delete(s.workspaceid >= 0 ? `${s.workspaceid}.RONIN_SESSION` : "RONIN_SESSION")
          }
        }
      }
    }
  } catch (e) {
    throw e
  }
  return { statusCode, response_headers, response_body }
}


function settings_get(workspaceid) {
  let s = workspace_settings[workspaceid]
  if (s) {
    s.workspaceid = workspaceid
  } else {
    s = settings
  }
  return s
}

function dat_authenticate(ua, s) {
  let url = DAT_AUTH_URL
  let headers = {
    'user-agent': ua,
    'content-type': 'application/x-www-form-urlencoded'
  }
  let body = ''
  const CT = String(parseInt(new Date().getTime()))
  let message = s.APP_KEY + CT
  let hb = createHmac('sha256', s.HM_KEY).update(message).digest('hex')
  body = `ID=${s.RONIN_ID || ""}&PW=${s.RONIN_PW || ""}&KY=${s.APP_KEY}&CT=${CT}&HB=${hb}`
  return { url, headers, body }
}

function get_dat(u, headers, sid, s) {
  let { server, board, key } = u
  let url = ''
  let new_headers = {
    ...headers,
    'Content-Type': 'application/x-www-form-urlencoded'
  }
  let payload = ''
  let url_path = `/v1/${server.replace(/\..+/, '')}/${board}/${key}`
  let message = `${url_path}${sid}${s.APP_KEY}`
  let hobo = createHmac('sha256', s.HM_KEY).update(message).digest('hex')
  payload = `sid=${sid}&hobo=${hobo}&appkey=${s.APP_KEY}`
  url = `${DAT_API_URL}${url_path}`
  return { url, headers: new_headers, payload, method: "POST" }
}

async function post_by_api(u, headers, payload, query, tools, s) {
  const { conf, simplefetch, log, siki_values } = tools
  let monakey = conf.get(s.workspaceid >= 0 ? `${s.workspaceid}.MonaKey` : "MonaKey")
  let { server, board, thread } = u
  if (!monakey || monakey.length !== 64) {
    monakey = '00000000-0000-0000-0000-000000000000'
  }
  let ua = s.POST_USER_AGENT || headers['user-agent']
  let new_headers = {
    // "Accept": 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    // "Accept-Encoding": 'gzip, identity',
    "Referer": headers['referer'],
    "User-Agent": ua
  }
  let new_query = { ...query }
  delete (new_query.oekaki_thread1)
  if (headers['cookie']) {
    new_headers["Cookie"] = headers['cookie']
  }

  if (s.RONIN_POST || new_query.mail.match(/#RONIN/)) {
    new_query.mail = new_query.mail.replace(`#RONIN.*`, "")
    let { RONIN_ID, RONIN_PW } = s
    if (RONIN_ID && RONIN_PW) {
      let ronin_session = conf.get(s.workspaceid >= 0 ? `${s.workspaceid}.RONIN_SESSION` : "RONIN_SESSION")
      if (!ronin_session) {
        const { body } = await simplefetch("https://2chv.tora3.net/futen.cgi", { "Content-Type": "application/x-www-form-urlencoded" }, "POST", `ID=${RONIN_ID}&PW=${RONIN_PW}`)
        ronin_session = body?.replace(/SESSION-ID=(\S+)\n*/s, "$1")
        if (ronin_session) {
          log.info("Loggined RONIN")
          conf.set(s.workspaceid >= 0 ? `${s.workspaceid}.RONIN_SESSION` : "RONIN_SESSION", ronin_session)
        }
      }
      if (ronin_session) {
        new_query.sid = ronin_session
      }
    }
  }

  let qs_order = ['submit', 'FROM', 'mail', 'MESSAGE', 'bbs', 'key', 'subject', 'time', 'oekaki_thread1', 'oekaki', 'sid']
  let [, device, device_version] = ua.match(/Monazilla\/1\.00 ([^\/]+)\/([\d\.]+)/) || [, 'unknown']
  let device_os = DEVICE_OS[device] || ['unknown']
  new_headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
  let nonce
  switch (device) {
    case '2chMate':
      qs_order = ['FROM', 'mail', 'MESSAGE', 'bbs', 'time', 'key', 'subject', 'submit', 'oekaki_thread1', 'oekaki', 'sid']
      new_headers['X-2ch-UA'] = `${device}/${device_version}`
      break
    case 'JaneStyle':
      new_headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      new_headers['Accept-Encoding'] = 'gzip, identity'
      break
    case 'Live5ch':
      break
    case 'En2ch':
      qs_order = ['bbs', 'key', 'time', 'FROM', 'mail', 'MESSAGE', 'submit', 'subject', 'oekaki_thread1', 'oekaki', 'sid']
      new_headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8'
      break
    case 'JaneStyle_Android':
      nonce = `${query.time}.000`
      new_query.seed_time = new_query.time
      new_query.oekaki_thread1 = ""
      qs_order = ['time', 'key', 'mail', 'submit', 'subject', 'FROM', 'MESSAGE', 'bbs', 'oekaki_thread1', 'oekaki', 'sid']
      new_headers['Accept'] = '*/*'
      new_headers['Accept-Encoding'] = 'gzip'
      new_headers['Accept-Language'] = 'ja'
      break
    case 'Ciisaa':
      nonce = `${query.time}.${String(new Date().getTime()).slice(10)}`
      new_headers['Accept'] = 'text/*'
      new_headers['Referer'] = new_headers.Referer.replace(/\/test\/read.cgi\/(\w+)\/\d+\//, "/$1/")
      new_headers['User-Agent'] = new_headers['User-Agent'].replace(/\sBuild\/.*$/, ")")
      qs_order = ['bbs', 'subject', 'key', 'time', 'FROM', 'mail', 'MESSAGE', 'submit', 'oekaki_thread1', 'oekaki', 'sid']
      break
  }
  if (!nonce) {
    let ut = String(new Date().getTime())
    nonce = ut.slice(0, 10) + '.' + ut.slice(10)
  }
  let { postSig } = create_postSig(nonce, new_query, new_headers, monakey, s)
  let url = `https://${server}/test/bbs.cgi`
  new_headers['X-PostNonce'] = nonce
  new_headers['X-APIKey'] = s.APP_KEY
  new_headers['X-PostSig'] = postSig
  new_headers['X-MonaKey'] = monakey

  let qs = []
  if (s.query_strings_order) {
    qs = s.query_strings_order
  }
  for (let k of qs_order) {
    let v = new_query[k]
    if (v !== undefined) {
      if (k === 'FROM' || k === 'mail' || k === 'MESSAGE' || k === 'submit' || k === 'subject' || k === 'oekaki') {
        v = encodeURIComponent(v)
      }
      qs.push(`${k}=${v}`)
    }
  }
  payload = qs.join('&')
  return { url, headers: new_headers, payload }
}

function create_postSig(nonce, query, headers, monakey, s) {
  let input = [query.bbs, query.key, query.time, query.FROM ?? '', query.mail ?? '', query.MESSAGE ?? '', query.subject ?? '', headers['User-Agent'], monakey, query.oekaki_thread1, nonce].map(x => x ?? '').join('<>')
  let postSig = createHmac('sha256', s.HM_KEY).update(input).digest('hex')
  return { postSig }
}


const parse_read_cgi = (headers, html) => {
  if (!html) return
  let lines = []
  let patterns = [parse_pattern3, parse_pattern1, parse_pattern2]
  for (let f of patterns) {
    let l = f(headers, html)
    if (l) {
      lines = l
      break
    }
  }
  return { dat: lines.join("\n") + "\n" }
}

const parse_pattern1 = (headers, html) => {
  const thread_regexp = new RegExp(/<div class="post" id="(\d+)".*?>(.*?)<\/div><br>/, 'g')
  const res_regexp = new RegExp(/<span class="number">(\d+)<\/span><span class="name">(.*?)<\/span><span class="date">(.*?)<\/span><span class="uid">(.*?)<\/span><\/div><div class="message"><span class="escaped">(.*?)<\/span><\/div>/)

  let lines = []
  let [, title] = html.match(/<title>([^\n]+)\s?\n?<\/title>/s) || []
  for (let res of html.matchAll(thread_regexp)) {
    let [, num, tags] = res
    if (num === undefined) continue
    let [, number, name, date, id, message] = tags.match(res_regexp) || []
    let [, nid, bebase, bp] = id?.match(/ID:([^<>]+).*?<a href=".*?\/(\d+)".*?\?([^<]+)<\/a>/) || []
    if (bp) {
      id = nid + `BE:${bebase}-${bp}`
    }
    let di = date + ' ' + id
    let [, mail, nname] = name?.match(/<a href="mailto:([^"]+)">(.*?)<\/a>/) || []
    if (mail !== undefined) {
      name = nname
    }
    let data
    if (message) {
      message = message.replace(/<span class="AA">(.*?)<\/span>$/, "$1")
      message = message.replace(/<a .*?href=.*?>((?:&gt;|http).*?)<\/a>/g, "$1")
      data = [name, mail ?? "", di, message]
    } else {
      data = ['', '', '', 'broken']
    }
    data.push(num == 1 ? title : "")
    lines.push(data.join("<>"))
  }

  return lines.length ? lines : undefined
}

const parse_pattern2 = (headers, html) => {
  const res_regexp = new RegExp(/<dt>(\d+) ：(.*?)：(.*?)<dd>(.*?)$/)

  let lines = []
  let [, title] = html.match(/<title>([^\n]+)\s?\n?<\/title>/s) || []
  for (let l of html.split("\n")) {
    let [, num, name, di, message] = l.match(res_regexp) || []
    if (num === undefined) continue
    let [, ndi, bebase, bp] = di?.match(/(.*?)<a href="javascript:be\((\d+)\);">\?(.*?)<\/a>$/) || []
    if (bp) {
      di = ndi + ` BE:${bebase}-${bp}`
    }
    name = name?.replace(/^<font color=.*?>(.*?)<\/font>$/, "$1")
    let [, mail, nname] = name?.match(/<a href="mailto:([^\"]+)">(.*?)<\/a>/) || []
    if (mail !== undefined) {
      name = nname
    }
    let data
    if (message) {
      message = message.replace(/<br><br>$/, "")
      message = message.replace(/<a href=.*?>(http.*?)<\/a>/g, "$1")
      data = [name, mail ?? "", di, message]
    } else {
      data = ['', '', '', 'broken']
    }
    data.push(num == 1 ? title : "")
    lines.push(data.join("<>"))
  }
  return lines.length ? lines : undefined
}

const parse_pattern3 = (headers, html) => {
  const thread_regexp = new RegExp(/<article id="(\d+)".*?>(.*?)<\/article>/, 'g')
  const res_regexp = new RegExp(/<span class="postusername">(.*?)<\/span><\/summary><span class="date">(.*?)<\/span><span class="uid">(.*?)<\/span>(?:<span class="be(.*?)<\/span>)?.*?<section class="post-content">(.*?)<\/section>/)

  let lines = []
  let [, title] = html.match(/<title>([^\n]+)\s?\n?<\/title>/s) || []
  for (let res of html.matchAll(thread_regexp)) {
    let [, num, tags] = res
    if (num === undefined) continue
    let [, name, date, id, bedata, message] = tags.match(res_regexp) || []
    let [, nid, bebase, bp] = bedata?.match(/<a href=".*?(\d+)".*?>\?([^<]+)<\/a>/) || []
    if (bp) {
      id = nid + `BE:${bebase}-${bp}`
    }
    let di = date + ' ' + id
    let [, mail, nname] = name?.match(/<a href="mailto:([^"]+)">(.*?)<\/a>/) || []
    if (mail !== undefined) {
      name = nname
    }
    let data
    if (message) {
      message = message.replace(/<span class="AA">(.*?)<\/span>$/, "$1")
      message = message.replace(/<a .*?href=.*?>((?:&gt;|http).*?)<\/a>/g, "$1")
      data = [name, mail ?? "", di, message]
    } else {
      data = ['', '', '', 'broken']
    }
    data.push(num == 1 ? title : "")
    lines.push(data.join("<>"))
  }

  return lines.length ? lines : undefined
}
