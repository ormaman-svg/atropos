/*
 * The Atropos mark.
 *
 * Three dots on a diagonal — a three-hop path — with one stroke cutting
 * across them at the point they align. Path, then cut. It is the whole
 * product in a glyph, and it is the name in geometry: Atropos is the Fate
 * who holds the shears.
 *
 * Inherited from the reference console's Orion's-belt mark, which is why the
 * dot positions are unchanged. The gold stroke is what makes it ours: the
 * belt says "three hops", the stroke says "one fix".
 *
 * The stroke runs perpendicular to the line of dots and passes through the
 * middle one, so it reads as a cut at any size. Legible down to 16px.
 */
export function Mark({ size = 30 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 30 30"
      role="img"
      aria-label="Atropos"
    >
      <line
        x1="7"
        y1="22.5"
        x2="23"
        y2="7.5"
        stroke="var(--color-navy)"
        strokeWidth="1.25"
      />
      <circle cx="7" cy="22.5" r="2.6" fill="var(--color-navy)" />
      <circle cx="15" cy="15" r="2.6" fill="var(--color-navy)" />
      <circle cx="23" cy="7.5" r="2.6" fill="var(--color-navy)" />
      <line
        x1="10.9"
        y1="10.6"
        x2="19.1"
        y2="19.4"
        stroke="var(--color-star)"
        strokeWidth="2.5"
        strokeLinecap="round"
      />
    </svg>
  );
}
