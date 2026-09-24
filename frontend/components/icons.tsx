/** Inline 16px icons (stroke-based, currentColor). No icon library dependency. */
type P = { size?: number };
const base = (size = 16) => ({
  width: size,
  height: size,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "square" as const,
  strokeLinejoin: "miter" as const,
});

export const IconGauge = ({ size }: P) => (
  <svg {...base(size)}><path d="M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z" /><path d="M13.4 10.6 19 5" /><path d="M20.8 16A9 9 0 1 0 3.2 16" /></svg>
);
export const IconFlame = ({ size }: P) => (
  <svg {...base(size)}><path d="M12 3c2 3.5.5 5 .5 5S16 8 17 12a5 5 0 1 1-10 0c0-2 1-3.5 2-4.5.5 1.5 1.5 2 1.5 2S9.5 6 12 3Z" /></svg>
);
export const IconBug = ({ size }: P) => (
  <svg {...base(size)}><rect x="8" y="6" width="8" height="14" rx="4" /><path d="M8 11H4m16 0h-4M8 16H4m16 0h-4M9 6 8 3m7 3 1-3" /></svg>
);
export const IconCode = ({ size }: P) => (
  <svg {...base(size)}><path d="m8 8-4 4 4 4m8-8 4 4-4 4m-2-11-4 14" /></svg>
);
export const IconUsers = ({ size }: P) => (
  <svg {...base(size)}><path d="M16 19v-1a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v1" /><circle cx="9" cy="7" r="3.2" /><path d="M22 19v-1a4 4 0 0 0-3-3.8M16.5 4.2a3.2 3.2 0 0 1 0 6" /></svg>
);
export const IconVirus = ({ size }: P) => (
  <svg {...base(size)}><circle cx="12" cy="12" r="5" /><path d="M12 3v2m0 14v2M3 12h2m14 0h2M5.6 5.6 7 7m10 10 1.4 1.4M18.4 5.6 17 7M7 17l-1.4 1.4" /></svg>
);
export const IconTarget = ({ size }: P) => (
  <svg {...base(size)}><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3.5" /></svg>
);
export const IconGrid = ({ size }: P) => (
  <svg {...base(size)}><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></svg>
);
export const IconDoc = ({ size }: P) => (
  <svg {...base(size)}><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z" /><path d="M14 3v5h5M9 13h6M9 17h4" /></svg>
);
export const IconNews = ({ size }: P) => (
  <svg {...base(size)}><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M7 9h6M7 13h10M7 16h10" /></svg>
);
export const IconShield = ({ size }: P) => (
  <svg {...base(size)}><path d="M12 3 5 6v6c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V6l-7-3Z" /></svg>
);
export const IconPulse = ({ size }: P) => (
  <svg {...base(size)}><path d="M3 12h4l2.5-7 4 14L16 12h5" /></svg>
);
export const IconSettings = ({ size }: P) => (
  <svg {...base(size)}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2V21a2 2 0 1 1-4 0v-.1A1.7 1.7 0 0 0 7 19.4a1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.9H1a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 2.6 7a1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.7 1.7 0 0 0 7 2.6h.1A1.7 1.7 0 0 0 8.3 1V1a2 2 0 1 1 4 0v.1A1.7 1.7 0 0 0 15 2.6" /></svg>
);
export const IconSearch = ({ size }: P) => (
  <svg {...base(size)}><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
);
export const IconBell = ({ size }: P) => (
  <svg {...base(size)}><path d="M18 8a6 6 0 1 0-12 0c0 7-2 8-2 8h16s-2-1-2-8" /><path d="M13.7 20a2 2 0 0 1-3.4 0" /></svg>
);
export const IconExternal = ({ size = 13 }: P) => (
  <svg {...base(size)}><path d="M14 4h6v6M20 4l-8 8M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" /></svg>
);
export const IconAlert = ({ size }: P) => (
  <svg {...base(size)}><path d="M12 4 2.5 20h19L12 4Z" /><path d="M12 10v4m0 3h.01" /></svg>
);
export const IconClock = ({ size }: P) => (
  <svg {...base(size)}><circle cx="12" cy="12" r="8.5" /><path d="M12 7.5V12l3 2" /></svg>
);
export const IconFingerprint = ({ size }: P) => (
  <svg {...base(size)}><path d="M12 11v3a7 7 0 0 1-1.5 4.3M8 8.5a5 5 0 0 1 8 4v1.5M5 12a7 7 0 0 1 3-5.8M19 14a12 12 0 0 1-.5 3.5" /><path d="M12 15a4 4 0 0 1-.8 2.5" /></svg>
);
