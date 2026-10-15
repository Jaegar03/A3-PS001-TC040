"use client";

import { useSyncExternalStore } from "react";

function subscribe(onChange: () => void) {
  const media = window.matchMedia?.("(prefers-reduced-motion: reduce)");
  if (!media) return () => {};
  if (media.addEventListener) {
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }
  media.addListener(onChange);
  return () => media.removeListener(onChange);
}

function snapshot() {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? true;
}

// A static server snapshot avoids hydration mismatch and pre-hydration motion.
export function useReducedMotion() {
  return useSyncExternalStore(subscribe, snapshot, () => true);
}
