defmodule Kelix.Mod.Mcu.Conference do
  @moduledoc """
  One conference (design `docs/design/mcu_module.md` §5.1).

  `uid` is the identity kelixip and its REST clients use, and it is also the MCU
  `tag` — which is how an event coming back up the stream is mapped to a
  conference. `conf_id` is the MCU-side integer and an implementation detail: it
  changes if the conference is recreated after an MCU restart (§5.3), so nothing
  outside the module keys on it.

  A conference is **pinned** to the MCU chosen at creation (`mcu`): there is no
  multi-MCU conference and no migration (§1.3).

  Participants are keyed by an internal `ref` rather than by `part_id`: the row is
  created by `admit/2` — which reserves the quota slot **before** anything exists
  MCU-side — and learns its `part_id` later, when the adapter has created the
  participant inside its own connection lifetime (§8.2).
  """

  @type participant :: %{
          ref: reference,
          part_id: non_neg_integer | nil,
          conf_uid: String.t(),
          name: String.t(),
          # the tile banner admit/3's `:displayname` option asked for, nil for none
          display_name: String.t() | nil,
          from: String.t() | nil,
          scenario: pid | nil,
          conn: pid | nil,
          state: :ringing | :connected | :leaving,
          medias: map,
          # §20: whether this leg's script declared it handles the collaboration
          # channel. Only a leg that did is ever sent a `{:mcu_message, …}`.
          accepts_messages: boolean,
          # P7/S1: per-media RTP silence, keyed by media atom. A leg is only
          # reaped once EVERY watched media (all but text) is silent, so this
          # is the AND's state — set by event 3, cleared by event 4.
          silent: %{optional(atom) => true},
          admitted_at: DateTime.t(),
          joined_at: DateTime.t() | nil
        }

  @type t :: %__MODULE__{}

  defstruct uid: nil,
            name: nil,
            domain: nil,
            did: nil,
            mcu: nil,
            conf_id: nil,
            vad: 1,
            rate: 32_000,
            # Which m= sections this conference answers at all (§8.4). The codecs inside
            # them are the media server's call since P8a — a conference holds no codec
            # list at all, which is what made `medias` necessary.
            medias: [:audio, :video, :text],
            dtmf: true,
            # RTP inactivity watchdog armed per media at the ACK (§16.1). Comes from
            # `[module.mcu] rtp_timeout_ms`; 0 disables it. Lives on the conference so
            # the adapter reads it off the leg it is setting up, like `video`.
            rtp_timeout_ms: 10_000,
            video: %{size: 6, fps: 15, bitrate: 1024, intra_period: 300},
            layout: %{comp: 1, size: 6, auto: true},
            max_participants: 20,
            destroy_when_empty: false,
            created_at: nil,
            # Set when the MCU holding this conference went away (§9.2): the row and
            # its DID survive, `conf_id` does not, and the conference is recreated
            # (same `uid`, new `conf_id`) when the server comes back. Visible in
            # `show`/`list` so an operator sees why a DID answers 503.
            stale: false,
            # §8.3.8. `logo` is the image drawn in every EMPTY mosaic slot (a basename
            # under the configured `image_dir`, on the media server).
            logo: nil,
            # The slots **we** pinned: `%{slot => wire value}`. The mixer's own
            # occupancy is not here — that is `GetMosaicPositions`, read on demand —
            # because this map is *policy*, and policy is what has to be replayed when
            # a restarted media server gets the conference recreated (§9.2).
            slots: %{},
            # `%{file, path, started_at}` while the mix is being recorded, else nil.
            # Held here because the server has no "am I recording?" RPC to ask.
            recording: nil,
            participants: %{}

  @doc "Live participants (every row `admit/2` reserved, including the ringing ones)."
  @spec participants(t) :: [participant]
  def participants(%__MODULE__{participants: map}), do: Map.values(map)

  @doc "How many slots are taken (a ringing leg holds one — that is the quota)."
  @spec count(t) :: non_neg_integer
  def count(%__MODULE__{participants: map}), do: map_size(map)

  @doc "Whether the conference has no room left."
  @spec full?(t) :: boolean
  def full?(%__MODULE__{} = conf), do: count(conf) >= conf.max_participants

  @doc "The participant with that MCU-side `part_id`, or `nil`."
  @spec by_part_id(t, non_neg_integer) :: participant | nil
  def by_part_id(%__MODULE__{} = conf, part_id),
    do: Enum.find(participants(conf), &(&1.part_id == part_id))

  @doc """
  The participant a **human-typed name** designates: its full name
  (`alice@phone_example_com`) or just the user part — nobody wants to type the first.

  `{:ambiguous, [part_id]}` when two legs of the same user match: a coin flip between
  them is never the right answer, and the caller can say which ids to choose from.
  Only legs that reached the mixer (`part_id` set) are candidates.

  One reading, two callers: pinning a mosaic slot by name (§8.3.8) and addressing a
  collaboration message by name (§20.4).
  """
  @spec by_name(t, String.t()) :: {:ok, participant} | :error | {:ambiguous, [pos_integer]}
  def by_name(%__MODULE__{} = conf, name) when is_binary(name) do
    wanted = name |> String.trim() |> String.downcase()

    case Enum.filter(participants(conf), &(is_integer(&1.part_id) and matches?(&1.name, wanted))) do
      [one] -> {:ok, one}
      [] -> :error
      many -> {:ambiguous, many |> Enum.map(& &1.part_id) |> Enum.sort()}
    end
  end

  defp matches?(nil, _wanted), do: false

  defp matches?(name, wanted) do
    name = String.downcase(name)
    name == wanted or hd(String.split(name, "@")) == wanted
  end

  @doc """
  A REST/CLI view of the conference: the operator-facing fields, participants
  summarised rather than dumped (pids and media detail are not an API).
  """
  @spec render(t) :: map
  def render(%__MODULE__{} = conf) do
    %{
      uid: conf.uid,
      name: conf.name,
      domain: conf.domain,
      did: conf.did,
      mcu: conf.mcu,
      conf_id: conf.conf_id,
      vad: conf.vad,
      rate: conf.rate,
      # what this conference answers, which is the policy the codec lists used to
      # express: the codecs themselves are the media server's and not ours to report
      medias: conf.medias,
      dtmf: conf.dtmf,
      video: conf.video,
      layout: conf.layout,
      max_participants: conf.max_participants,
      destroy_when_empty: conf.destroy_when_empty,
      created_at: conf.created_at,
      stale: conf.stale,
      logo: conf.logo,
      # the file, not the map: `recording.show` is where the detail lives
      recording: conf.recording && conf.recording.file,
      participants: count(conf)
    }
  end

  @doc "A REST/CLI view of one participant row."
  @spec render_participant(participant) :: map
  def render_participant(part) do
    %{
      part_id: part.part_id,
      name: part.name,
      from: part.from,
      state: part.state,
      medias: part.medias,
      joined_at: part.joined_at
    }
  end
end
