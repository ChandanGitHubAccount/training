package FirstEavluation;

import java.util.Map;
import java.util.Scanner;

public class FrontDesk implements FrontDeskToSystemInterface {
    static Scanner scan = new Scanner(System.in);
    static CustomerToSystemInterface customer = new OnlineMovieTicketBookingSystem();
    static OnlineMovieTicketBookingSystem onlineMovieTicketBookingSystem = new OnlineMovieTicketBookingSystem();

    @Override
    public void bookTicket(Map<String, RegisteredCustomersDetails> customersDetails) {
        System.out.println("Enter customer Id");
        String customerId = scan.next();
        if (customersDetails.containsKey(customerId)) {
            onlineMovieTicketBookingSystem.displayRunningCinemas();
            System.out.println("Select movie name from list.");
            String movieName = scan.next();
            customer.searchMoviesByMovieName(movieName, customerId);
        }
    }

    @Override
    public void cancelTicket(String customerId, Map<String, City> city, Map<String, RegisteredCustomersDetails> customersDetails) {
        System.out.println("enter the number of u want to cancel.");
        int cancelingSeats = scan.nextInt();
        if (customersDetails.get(customerId).getCurrentBookedSeats() > cancelingSeats) {
            System.out.println("Your money " + cancelingSeats * 150 + " will be refunded to your account in 2 working days");
            int remainingSeats = customersDetails.get(customerId).getCurrentBookedSeats() - cancelingSeats;
            customersDetails.get(customerId).setCurrentBookedSeats(remainingSeats);
        } else
            System.out.println("your current booked seats are less than canceling seats so cannot cancel seats.Enter valid number of seats for canceling");
    }

    @Override
    public void SendNotifications(Map<String, RegisteredCustomersDetails> customersDetails) {
        for (String key : customersDetails.keySet()) {
            System.out.println("Enter the notification message want to send to customer.");
            String notificationMessage = scan.next();
            String oldNotification = customersDetails.get(key).getNotifications();
            String newNotification = notificationMessage + "\n" + oldNotification;
            customersDetails.get(key).setNotifications(newNotification);
        }
    }
}
