export const DEFAULT_DEVELOPMENT_ONBOARDING_WINDOW_SECONDS = 15 * 60;
export const DEVELOPMENT_ONBOARDING_CLOCK_SKEW_SECONDS = 15;

export function developmentOnboardingWindowMs(seconds?: number) {
  return (seconds ?? DEFAULT_DEVELOPMENT_ONBOARDING_WINDOW_SECONDS) * 1000;
}
