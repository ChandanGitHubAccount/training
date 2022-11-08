package FirstEavluation;

import java.util.*;


public class OnlineMovieTicketBookingSystem implements GuestsInterface, SystemInterface, CustomerToSystemInterface {
    static Scanner scan = new Scanner(System.in);
    static Map<String, City> city = new HashMap<>();
    static Admins admin = new Admins();
    static FrontDesk frontDesk = new FrontDesk();
    static Map<String, RegisteredCustomersDetails> customersDetails = new HashMap<>();
    static CustomerToSystemInterface customer = new OnlineMovieTicketBookingSystem();
    static GuestsInterface guests = new OnlineMovieTicketBookingSystem();

    public static void main(String[] args) {
        setCitiesAndTheatres();
        while (true) {
            System.out.println("select \n1:Admin.\n2:Front desk.\n3:Customer.\n4:Guest.\n5:Exit.");
            int choice = scan.nextInt();
            switch (choice) {
                case 1 -> adminLogin();
                case 2 -> fontDeskLogin();
                case 3 -> customerLogin();
                case 4 -> guestLogin();
                case 5 -> {
                    return;
                }
                default -> {
                    System.out.println("INVALID CHOICE");
                    main(args);
                }
            }
        }
    }

    private static int[][] setNumberOfSeats() {
        return new int[][]{{1, 2, 3, 4}, {5, 6, 7, 8}, {9, 10, 11, 12}, {13, 14, 15, 16}};
    }

    private static void guestLogin() {
        System.out.println("Select \n1:Search movie.\n2:New Registration");
        if (scan.nextInt() == 1)
            guests.SearchMovies();
        else if (scan.nextInt() == 2) {
            System.out.println("Enter firstname , lastname , phone number and email.");
            String firstName = scan.next();
            String lastName = scan.next();
            long phoneNumber = scan.nextLong();
            String eMail = scan.next();
            newRegistration(firstName, lastName, eMail, phoneNumber);
        }
    }

    public static String generateCustomerId(int lengthOfId) {
        Random random = new Random();
        StringBuilder patientId = new StringBuilder();
        int lengthOfChar = lengthOfId - 4;
        int lengthOfInt = lengthOfId - lengthOfChar;
        for (int index = 0; index < lengthOfChar; index++) {
            char character = (char) (97 + random.nextInt(26));
            patientId.append(character);
        }
        for (int index = 0; index < lengthOfInt; index++) {
            char number = (char) (48 + random.nextInt(10));
            patientId.append(number);
        }
        return patientId.toString();
    }

    private static void newRegistration(String firstName, String lastName, String eMail, long phoneNumber) {
        String customerId = generateCustomerId(8);
        if (customersDetails.containsKey(customerId))
            newRegistration(firstName, lastName, eMail, phoneNumber);
        else
            customersDetails.put(customerId, new RegisteredCustomersDetails(customerId, firstName, lastName, eMail, phoneNumber));

    }

    private static void customerLogin() {
        System.out.println("Enter customer ID.");
        String customerId = scan.next();
        if (customersDetails.containsKey(customerId)) {
            System.out.println("Select \n1:Search Movies By Movie Name.\2:Search Movies By City Name.\n3:Search Movies By Genre.\n4:Search Movies By Language.");
            switch (scan.nextInt()) {
                case 1 -> {
                    displayMovieNames();
                    System.out.println("Select proper movie name from list");
                    String movieName = scan.next();
                    customer.searchMoviesByMovieName(movieName, customerId);
                }
                case 2 -> {
                    displayCities();
                    System.out.println("Select proper city name from list");
                    String cityName = scan.next();
                    customer.searchMoviesByCityName(cityName, customerId);
                }
                case 3 -> {
                    displayMovieGenreAvailable();
                    System.out.println("Select proper movie genre from list");
                    String genre = scan.next();
                    customer.searchMoviesByMovieGenre(genre, customerId);
                }
                case 4 -> {
                    displayMovieLanguages();
                    System.out.println("Select proper movie language from list");
                    String language = scan.next();
                    customer.searchMoviesByMovieLanguage(language, customerId);
                }
                default -> {
                    System.out.println("INVALID CHOICE");
                    customerLogin();
                }
            }
        } else System.out.println("INVALID CUSTOMER ID.");
    }

    private static void displayMovieLanguages() {
        System.out.println("[");
        for (String key : city.keySet())
            System.out.println(city.get(key).getTheatreHalls().getScreens().getCinemas().getMovieLanguage());
        System.out.println("]");
    }

    private static void displayMovieGenreAvailable() {
        System.out.println("[");
        for (String key : city.keySet())
            System.out.println(city.get(key).getTheatreHalls().getScreens().getCinemas().getGenre());
        System.out.println("]");
    }

    private static void displayMovieNames() {
        System.out.println("[");
        for (String key : city.keySet())
            System.out.println(city.get(key).getTheatreHalls().getScreens().getCinemas().getNameOfMovie());
        System.out.println("]");
    }

    private static void displayCities() {
        System.out.println("[");
        for (String key : city.keySet())
            System.out.println(city.get(key).getCityName());
        System.out.println("]");
    }

    private static void fontDeskLogin() {
        System.out.println("Select \n1:Book Ticket.\n2:Cancel Ticket\n3:Send notification to customers.");
        switch (scan.nextInt()) {
            case 1 -> frontDesk.bookTicket(customersDetails);
            case 2 -> {
                System.out.println("Enter customer id.");
                String customerId = scan.next();
                if (customersDetails.containsKey(customerId))
                    frontDesk.cancelTicket(customerId, city, customersDetails);
            }
            case 3 -> frontDesk.SendNotifications(customersDetails);
            default -> {
                System.out.println("INVALID CHOICE");
                fontDeskLogin();
            }
        }
    }

    private static void adminLogin() {
        System.out.println("Select \n1:Display Theatres Where Movies Will Run.\n2:Add Or Modify Movie");
        switch (scan.nextInt()) {
            case 1 -> admin.displayTheatresWhereMoviesWillRun(city);
            case 2 -> {
                System.out.println(city.keySet());
                System.out.println("Enter City Id in which movie want to be Modified with new movie.");
                String cityId = scan.next();
                admin.addOrModifyMovie(cityId, city);
            }
            default -> {
                System.out.println("INVALID CHOICE");
                adminLogin();
            }
        }
    }

    private static void setCitiesAndTheatres() {
        city.put("CT01TH01SC01M1", new City("CT01TH01SC01M1", "bang-lore",
                new TheatreHalls("TH01", "Arhirvad", 3,
                        new Screens("SC01", "M1", "TH01", 4, 16,
                                new Cinemas("M1", "Kanthara", "Kannada", "Devotional"), setNumberOfSeats()))));
        city.put("CT01TH01SC02M2", new City("CT01TH01SC02M2", "bang-lore",
                new TheatreHalls("TH01", "Arhirvad", 3,
                        new Screens("SC02", "M2", "TH01", 4, 16,
                                new Cinemas("M2", "Vikram Veda", "Tamil", "Action"), setNumberOfSeats()))));
        city.put("CT01TH01SC03M3", new City("CT01TH01SC03M3", "bang-lore",
                new TheatreHalls("TH01", "Arhirvad", 3,
                        new Screens("SC03", "M3", "TH01", 4, 16,
                                new Cinemas("M3", "Black panther", "English", "Drama"), setNumberOfSeats()))));
        city.put("CT01TH02SC01M1", new City("CT01TH02SC01M1", "bang-lore",
                new TheatreHalls("TH02", "Santhekatte", 1,
                        new Screens("SC01", "M1", "TH02", 4, 16,
                                new Cinemas("M1", "Goodbye", "Hindi", "Devotional"), setNumberOfSeats()))));
        city.put("CT02TH01SC02M2", new City("CT02TH01SC02M2", "Hassan",
                new TheatreHalls("TH01", "Pruthvi", 1,
                        new Screens("SC01", "M1", "TH01", 4, 16,
                                new Cinemas("M1", "Vikram Veda", "Tamil", "Action"), setNumberOfSeats()))));

    }

    //guest
    @Override
    public void SearchMovies() {
        displayMovieNames();
    }

    //system
    @Override
    public void displayRunningCinemas() {
        for (String key : city.keySet())
            System.out.println(city.get(key).getTheatreHalls().getScreens().getCinemas().toString());
    }

    //customer service
    @Override
    public void searchMoviesByMovieName(String movieName, String customerId) {
        try {
            for (String key : city.keySet())
                if (city.get(key).getTheatreHalls().getScreens().getCinemas().getNameOfMovie().equals(movieName)) {
                    System.out.println(city.get(key).getTheatreHalls().getScreens().getCinemas().toString());
                    System.out.println("Enter 1 to book Ticket or else anything to not book ticket");
                    if (scan.nextInt() == 1)
                        customer.selectParticularShows(key, customerId);
                    else System.out.println("Not interested in movie.");
                }
        } catch (Exception exception) {
            exception.printStackTrace();
            System.exit(0);
        }
    }

    @Override
    public void searchMoviesByCityName(String cityName, String customerId) {
        try {
            for (String key : city.keySet())
                if (city.get(key).getCityName().equals(cityName)) {
                    System.out.println(city.get(key).getTheatreHalls().getScreens().getCinemas().toString());
                    System.out.println("Enter 1 to book Ticket or else anything to not book ticket");
                    if (scan.nextInt() == 1)
                        customer.selectParticularShows(key, customerId);
                    else System.out.println("Not interested in movie.");
                }
        } catch (Exception exception) {
            exception.printStackTrace();
            System.exit(0);
        }
    }

    @Override
    public void searchMoviesByMovieGenre(String genre, String customerId) {
        try {
            for (String key : city.keySet())
                if (city.get(key).getTheatreHalls().getScreens().getCinemas().getGenre().equals(genre)) {
                    System.out.println(city.get(key).getTheatreHalls().getScreens().getCinemas().toString());
                    System.out.println("Enter 1 to book Ticket or else anything to not book ticket");
                    if (scan.nextInt() == 1)
                        customer.selectParticularShows(key, customerId);
                    else System.out.println("Not interested in movie.");
                }
        } catch (Exception exception) {
            exception.printStackTrace();
            System.exit(0);
        }
    }

    @Override
    public void searchMoviesByMovieLanguage(String language, String customerId) {
        try {
            for (String key : city.keySet())
                if (city.get(key).getTheatreHalls().getScreens().getCinemas().getMovieLanguage().equals(language)) {
                    System.out.println(city.get(key).getTheatreHalls().getScreens().getCinemas().toString());
                    System.out.println("Enter 1 to book Ticket or else anything to not book ticket");
                    if (scan.nextInt() == 1)
                        customer.selectParticularShows(key, customerId);
                    else System.out.println("Not interested in movie.");
                }
        } catch (Exception exception) {
            exception.printStackTrace();
            System.exit(0);
        }
    }

    @Override
    public int makePaymentToBookTicket(int numberOfSeats, String paymentMethod) {
        System.out.println("Select Payment method\n[CREDITCARD,CASH]");
        if (scan.next().equals(PaymentMethods.CREDITCARD.toString()))
            System.out.println("entered credit card number and waiting...");
        else if (scan.next().equals(PaymentMethods.CASH.toString()))
            System.out.println("Paying cash...");
        else System.out.println("INVALID CHOICE.");
        return numberOfSeats * 150;
    }

    @Override
    public void selectParticularShows(String key, String customerId) {
        System.out.println(Arrays.toString(ShowTimings.values()));
        System.out.println("Select show in available list.");
        String show = scan.next().toUpperCase();
        try {
            System.out.println(show + " selected.");
            chooseSeats(key);
            System.out.println("enter number of seats you want to book.");
            int numberOfSeats = scan.nextInt();
            if (city.get(key).getTheatreHalls().getScreens().getMaximumNumberOfSeats() > numberOfSeats) {
                updateSeatInScreen(key, numberOfSeats);
                int remainingSeats = city.get(key).getTheatreHalls().getScreens().getMaximumNumberOfSeats() - numberOfSeats;
                city.get(key).getTheatreHalls().getScreens().setMaximumNumberOfSeats(remainingSeats);
                String paymentMethod = selectPaymentMethod();
                customersDetails.get(customerId).setCurrentBookedSeats(numberOfSeats);
                System.out.println("Payment done for booking ticket of rupees : " + customer.makePaymentToBookTicket(numberOfSeats, paymentMethod));
            } else System.out.println("Seats are full.");
        } catch (Exception exception) {
            System.out.println("Invalid choice.");
            selectParticularShows(key, customerId);
        }
    }

    private void updateSeatInScreen(String key, int numberOfSeats) {
        for (int index = 0; index < numberOfSeats; index++) {
            System.out.println("Enter the seat numbers u want to choose");
            int seatNumber = scan.nextInt();
            if (verifySeatAvailability(seatNumber, key))
                System.out.println("Seat is allocated.");
            else
                System.out.println("This Seat Full Choose other seat.");
        }
    }

    private boolean verifySeatAvailability(int seatNumber, String key) {
        int[][] seatsArrangements = city.get(key).getTheatreHalls().getScreens().getSeats();
        for (int row = 0; row < seatsArrangements.length; row++)
            for (int column = 0; column < seatsArrangements[row].length; column++)
                if (seatsArrangements[row][column] == seatNumber) {
                    Screens.resetAllocatedSeats(seatNumber, row, column);
                    return true;
                }
        return false;
    }

    private String selectPaymentMethod() {
        System.out.println("Select Payment method\n[CREDITCARD,CASH]");
        String paymentMethod = null;
        try {
            paymentMethod = String.valueOf(PaymentMethods.valueOf(scan.next().toUpperCase()));
        } catch (Exception exception) {
            System.out.println("INVALID CHOICE.");
            selectPaymentMethod();
        }
        return paymentMethod;
    }

    @Override
    public void chooseSeats(String key) {
        int[][] seatsArrangements = city.get(key).getTheatreHalls().getScreens().getSeats();
        for (int[] seatsArrangement : seatsArrangements) {
            for (int row : seatsArrangement) {
                System.out.print(row + " ");
            }
            System.out.println();
        }


    }
}
