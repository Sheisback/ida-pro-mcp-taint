/* Owned static-analysis fixture for a security-cookie entry wrapper. Never load. */
#define EXPORT __attribute__((dllexport, noinline))

static volatile int cookie_state;

EXPORT void CookieInit(void) {
  cookie_state = 1;
}

EXPORT int DriverEntry(void *driver_object, void *registry_path) {
  (void)registry_path;
  return driver_object == 0;
}

EXPORT int GsDriverEntry(void *driver_object, void *registry_path) {
  CookieInit();
  return DriverEntry(driver_object, registry_path);
}
