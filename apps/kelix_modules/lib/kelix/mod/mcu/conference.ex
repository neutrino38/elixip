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
            codecs: %{audio: [], video: [], text: []},
            dtmf: true,
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
      codecs: conf.codecs,
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
