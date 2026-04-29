# ===================
# ©AngelaMos | 2026
# event_bus.cr
# ===================

require "log"
require "../events/event"

module CRE::Engine
  class EventBus
    Log = ::Log.for("cre.event_bus")

    enum Overflow
      Block
      Drop
    end

    record Subscription, channel : Channel(Events::Event), overflow : Overflow

    @inbox : Channel(Events::Event)
    @subs : Array(Subscription)
    @subs_mutex : Mutex
    @running : Bool

    def initialize(inbox_capacity : Int32 = 1024)
      @inbox = Channel(Events::Event).new(capacity: inbox_capacity)
      @subs = [] of Subscription
      @subs_mutex = Mutex.new
      @running = false
    end

    def subscribe(buffer : Int32 = 64, overflow : Overflow = Overflow::Block) : Channel(Events::Event)
      ch = Channel(Events::Event).new(capacity: buffer)
      @subs_mutex.synchronize { @subs << Subscription.new(ch, overflow) }
      ch
    end

    def publish(event : Events::Event) : Nil
      @inbox.send(event)
    end

    def run : Nil
      @running = true
      spawn(name: "event-bus") do
        while @running
          begin
            ev = @inbox.receive
          rescue Channel::ClosedError
            break
          end
          @subs_mutex.synchronize { @subs.dup }.each { |s| dispatch(s, ev) }
        end
      end
    end

    def stop : Nil
      @running = false
      @inbox.close
      @subs_mutex.synchronize do
        @subs.each(&.channel.close)
      end
    end

    private def dispatch(sub : Subscription, ev : Events::Event) : Nil
      case sub.overflow
      in Overflow::Block
        sub.channel.send(ev)
      in Overflow::Drop
        select
        when sub.channel.send(ev)
          # delivered
        else
          Log.warn { "subscriber drop: #{ev.class.name}" }
        end
      end
    rescue Channel::ClosedError
      # subscriber gone; remove from list lazily on next dispatch
    end
  end
end
