const REQUIRED_VERIFICATION_CHECKS = ["validity_dates", "hostname", "chain"];

export function isCertificateVerified(certificate = {}) {
  return (
    String(certificate.status || "").toLowerCase() === "valid" &&
    certificate.valid === true &&
    REQUIRED_VERIFICATION_CHECKS.every(
      (check) => certificate.verification?.[check] === "verified",
    )
  );
}

export function getCertificateDisplayStatus(certificate = {}) {
  const status = String(certificate.status || "unavailable").toLowerCase();
  return status === "valid" && !isCertificateVerified(certificate)
    ? "unverified"
    : status;
}
