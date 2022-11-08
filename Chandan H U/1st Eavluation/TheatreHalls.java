package FirstEavluation;

public class TheatreHalls {
    private String theatreHallId, nameOfHall;
    private int numberOfScreen;
    private Screens screens;

    public Screens getScreens() {
        return screens;
    }

    public void setScreens(Screens screens) {
        this.screens = screens;
    }

    public TheatreHalls(String theatreHallId, String nameOfHall, int numberOfScreen, Screens screens) {
        this.theatreHallId = theatreHallId;
        this.nameOfHall = nameOfHall;
        this.screens = screens;
        this.numberOfScreen = numberOfScreen;
    }

    public String getTheatreHallId() {

        return theatreHallId;
    }

    public void setTheatreHallId(String theatreHallId) {
        this.theatreHallId = theatreHallId;
    }

    public String getNameOfHall() {
        return nameOfHall;
    }

    public void setNameOfHall(String nameOfHall) {
        this.nameOfHall = nameOfHall;
    }

    public int getNumberOfScreen() {
        return numberOfScreen;
    }

    public void setNumberOfScreen(int numberOfScreen) {
        this.numberOfScreen = numberOfScreen;
    }

    @Override
    public String toString() {
        return "TheatreHalls{" +
                "theatreHallId='" + theatreHallId + '\'' +
                ", nameOfHall='" + nameOfHall + '\'' +
                ", numberOfScreen=" + numberOfScreen +
                '}';
    }
}
