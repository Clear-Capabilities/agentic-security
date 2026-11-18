// Synthetic fixture: the write handler was copied from the read handler, checks included.
public class ReadingResource {
    public Reading[] getReadings(String deviceId) {
        Device device = devices.find(deviceId);
        if (!isAuthenticated() && !device.isPublicRead()) {
            throw new WebApplicationException(Response.Status.FORBIDDEN);
        }
        if (isAuthenticated() && !hasRole(Role.READ_DEVICES)) {
            throw new WebApplicationException(Response.Status.FORBIDDEN);
        }
        return readings.list(deviceId);
    }

    public void writeReadings(String deviceId, Reading[] values) {
        Device device = devices.find(deviceId);
        if (!isAuthenticated() && !device.isPublicRead()) {
            throw new WebApplicationException(Response.Status.FORBIDDEN);
        }
        if (isAuthenticated() && !hasRole(Role.READ_DEVICES)) {
            throw new WebApplicationException(Response.Status.FORBIDDEN);
        }
        readings.store(deviceId, values);
    }
}
