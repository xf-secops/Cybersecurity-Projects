# ===================
# ©AngelaMos | 2026
# system_events.cr
# ===================

require "./event"

module CRE::Events
  enum Severity
    Info
    Warn
    Critical
  end

  class AlertRaised < Event
    getter severity : Severity
    getter message : String

    def initialize(@severity : Severity, @message : String)
      super()
    end
  end

  class SchedulerTick < Event
  end

  class ShutdownRequested < Event
  end
end
