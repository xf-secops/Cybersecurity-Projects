# ===================
# ©AngelaMos | 2026
# telegram.cr
# ===================

require "http/client"
require "json"
require "log"

module CRE::Notifiers
  # Thin Telegram Bot API client. We hit api.telegram.org/bot<TOKEN>/<METHOD>
  # directly with HTTP::Client; no tourmaline dependency for the notification
  # path keeps the footprint small.
  class Telegram
    Log         = ::Log.for("cre.telegram")
    DEFAULT_API = "https://api.telegram.org"

    class TelegramError < Exception
      getter status : Int32

      def initialize(message : String, @status : Int32)
        super(message)
      end
    end

    record Update,
      update_id : Int64,
      message_id : Int64?,
      chat_id : Int64?,
      text : String?

    def initialize(@token : String, @api_base : String = DEFAULT_API)
    end

    def send_message(chat_id : Int64, text : String, parse_mode : String? = nil) : Nil
      payload = {"chat_id" => chat_id, "text" => text} of String => String | Int64
      payload["parse_mode"] = parse_mode if parse_mode
      call("sendMessage", payload.to_json)
    end

    def get_updates(offset : Int64? = nil, timeout : Int32 = 30) : Array(Update)
      h = {"timeout" => timeout} of String => String | Int64 | Int32
      h["offset"] = offset if offset
      json = call("getUpdates", h.to_json)
      results = json["result"].as_a
      results.map do |entry|
        msg = entry["message"]?
        Update.new(
          update_id: entry["update_id"].as_i64,
          message_id: msg.try(&.["message_id"]?.try(&.as_i64)),
          chat_id: msg.try(&.["chat"]?.try(&.["id"]?.try(&.as_i64))),
          text: msg.try(&.["text"]?.try(&.as_s)),
        )
      end
    end

    private def call(method : String, body : String) : JSON::Any
      uri = "#{@api_base}/bot#{@token}/#{method}"
      headers = HTTP::Headers{"Content-Type" => "application/json"}
      response = HTTP::Client.post(uri, headers: headers, body: body)
      raise TelegramError.new("telegram #{method} #{response.status_code}: #{response.body[0, 200]?}", response.status_code) unless response.status_code < 300
      JSON.parse(response.body)
    end
  end
end
