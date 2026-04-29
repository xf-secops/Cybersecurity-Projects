# ===================
# ©AngelaMos | 2026
# audit_subscriber.cr
# ===================

require "../event_bus"
require "../../audit/audit_log"
require "../../events/credential_events"
require "../../events/system_events"

module CRE::Engine::Subscribers
  class AuditSubscriber
    @ch : Channel(Events::Event)?
    @running : Bool

    def initialize(@bus : EventBus, @log : Audit::AuditLog, @actor : String = "system")
      @running = false
    end

    def start : Nil
      @running = true
      ch = @bus.subscribe(buffer: 256, overflow: EventBus::Overflow::Block)
      @ch = ch
      spawn(name: "audit-sub") do
        while @running
          begin
            ev = ch.receive
          rescue Channel::ClosedError
            break
          end
          handle(ev)
        end
      end
    end

    def stop : Nil
      @running = false
      @ch.try(&.close)
    end

    private def handle(ev : Events::Event) : Nil
      case ev
      when Events::RotationCompleted
        @log.append("rotation.completed", @actor, ev.credential_id, {
          "rotation_id" => ev.rotation_id.to_s,
        })
      when Events::RotationFailed
        @log.append("rotation.failed", @actor, ev.credential_id, {
          "rotation_id" => ev.rotation_id.to_s,
          "reason"      => ev.reason,
        })
      when Events::RotationStepCompleted
        @log.append("rotation.step.completed", @actor, ev.credential_id, {
          "rotation_id" => ev.rotation_id.to_s,
          "step"        => ev.step.to_s,
        })
      when Events::RotationStepFailed
        @log.append("rotation.step.failed", @actor, ev.credential_id, {
          "rotation_id" => ev.rotation_id.to_s,
          "step"        => ev.step.to_s,
          "error"       => ev.error,
        })
      when Events::PolicyViolation
        @log.append("policy.violation", @actor, ev.credential_id, {
          "policy_name" => ev.policy_name,
          "reason"      => ev.reason,
        })
      when Events::DriftDetected
        @log.append("drift.detected", @actor, ev.credential_id, {
          "expected_hash" => ev.expected_hash,
          "actual_hash"   => ev.actual_hash,
        })
      when Events::CredentialDiscovered
        @log.append("credential.discovered", @actor, ev.credential_id, {} of String => String)
      when Events::AlertRaised
        @log.append("alert.raised", @actor, nil, {
          "severity" => ev.severity.to_s,
          "message"  => ev.message,
        })
      end
    rescue ex
      EventBus::Log.error(exception: ex) { "audit subscriber failed to write" }
    end
  end
end
