import React from "react";

interface WatsonLogoProps {
  size?: number;
  className?: string;
}

/**
 * Watson v1 "A Study in Scarlet" logo — block-letter W
 * Based on the CLI ASCII art banner.
 */
export default function WatsonLogo({ size = 28, className }: WatsonLogoProps) {
  return (
    <svg
      width={size}
      height={size * 0.85}
      viewBox="0 0 48 41"
      fill="none"
      className={className}
      aria-label="Watson OSINT"
    >
      {/* W block letter */}
      <rect x="2" y="2" width="8" height="8" rx="0.5" fill="currentColor" />
      <rect x="38" y="2" width="8" height="8" rx="0.5" fill="currentColor" />
      <rect x="2" y="12" width="8" height="8" rx="0.5" fill="currentColor" />
      <rect x="12" y="12" width="6" height="8" rx="0.5" fill="currentColor" />
      <rect x="30" y="12" width="6" height="8" rx="0.5" fill="currentColor" />
      <rect x="38" y="12" width="8" height="8" rx="0.5" fill="currentColor" />
      <rect x="10" y="22" width="6" height="8" rx="0.5" fill="currentColor" />
      <rect x="18" y="22" width="12" height="8" rx="0.5" fill="currentColor" />
      <rect x="32" y="22" width="6" height="8" rx="0.5" fill="currentColor" />
      <rect x="16" y="32" width="7" height="7" rx="0.5" fill="currentColor" />
      <rect x="25" y="32" width="7" height="7" rx="0.5" fill="currentColor" />
    </svg>
  );
}
