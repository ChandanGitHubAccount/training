package FirstEavluation;

public class City {
    private String cityId ,cityName , theatreHallId;
    private TheatreHalls theatreHalls;

    public City(String cityId, String cityName,TheatreHalls theatreHalls) {
        this.cityId = cityId;
        this.cityName = cityName;
        this.theatreHalls = theatreHalls;
    }

    public String getCityId() {
        return cityId;
    }

    public void setCityId(String cityId) {
        this.cityId = cityId;
    }

    public TheatreHalls getTheatreHalls() {
        return theatreHalls;
    }

    public void setTheatreHalls(TheatreHalls theatreHalls) {
        this.theatreHalls = theatreHalls;
    }

    public String getCityName() {
        return cityName;
    }

    public void setCityName(String cityName) {
        this.cityName = cityName;
    }

    public String getTheatreHallId() {
        return theatreHallId;
    }

    public void setTheatreHallId(String theatreHallId) {
        this.theatreHallId = theatreHallId;
    }
}
