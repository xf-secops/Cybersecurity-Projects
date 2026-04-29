# ===================
# ©AngelaMos | 2026
# engine.cr
# ===================

require "log"
require "./event_bus"
require "./subscribers/audit_subscriber"
require "../audit/audit_log"
require "../persistence/persistence"

module CRE::Engine
  class Engine
    Log = ::Log.for("cre.engine")

    getter bus : EventBus
    getter persistence : Persistence::Persistence
    getter audit_log : Audit::AuditLog

    @audit_subscriber : Subscribers::AuditSubscriber
    @started : Bool

    def initialize(@persistence : Persistence::Persistence, hmac_key : Bytes, hmac_version : Int32 = 1, ratchet_every : Int32 = 1024)
      @bus = EventBus.new
      @audit_log = Audit::AuditLog.new(@persistence, hmac_key, hmac_version, ratchet_every)
      @audit_subscriber = Subscribers::AuditSubscriber.new(@bus, @audit_log)
      @started = false
    end

    def start : Nil
      raise "engine already started" if @started
      @started = true
      @audit_subscriber.start
      @bus.run
      Log.info { "engine started" }
    end

    def stop : Nil
      return unless @started
      Log.info { "engine stopping" }
      @bus.publish(Events::ShutdownRequested.new) rescue nil
      sleep 0.05.seconds # let subscribers see it
      @audit_subscriber.stop
      @bus.stop
      @started = false
      Log.info { "engine stopped" }
    end
  end
end
