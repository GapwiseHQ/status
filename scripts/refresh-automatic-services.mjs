// Keep each service's three-probe policy while bounding concurrent HTTP work.
export async function refreshAutomaticServices(groups, checks, probe, checkedAt) {
  const services = groups.flatMap((group) => group.services || [])
    .filter((service) => service.monitoring === "automatic");
  const pending = services[Symbol.iterator]();
  await Promise.all(Array.from({ length: Math.min(4, services.length) }, async () => {
    for (const service of pending) {
      const check = checks.get(service.id);
      if (!check) {
        service.status = "unknown";
        service.detail = "No automated probe is configured";
      } else {
        const result = await probe(check);
        service.url = check.url;
        service.status = result.status;
        service.detail = result.detail;
      }
      service.checkedAt = checkedAt;
    }
  }));
}
