package FirstEavluation;

public class RegisteredCustomersDetails {
    private String customerId, customerFirstName, customerLastName, customerEmail , notifications;
    private long customerPhoneNumber;
    private int currentBookedSeats;

    public String getNotifications() {
        return notifications;
    }

    public void setNotifications(String notifications) {
        this.notifications = notifications;
    }

    public int getCurrentBookedSeats() {
        return currentBookedSeats;
    }

    public void setCurrentBookedSeats(int currentBookedSeats) {
        this.currentBookedSeats = currentBookedSeats;
    }

    public RegisteredCustomersDetails(String customerId, String customerFirstName, String customerLastName, String customerEmail, long customerPhoneNumber) {
        this.customerId = customerId;
        this.customerFirstName = customerFirstName;
        this.customerLastName = customerLastName;
        this.customerEmail = customerEmail;
        this.customerPhoneNumber = customerPhoneNumber;
    }

    public String getCustomerId() {
        return customerId;
    }

    public void setCustomerId(String customerId) {
        this.customerId = customerId;
    }

    public String getCustomerFirstName() {
        return customerFirstName;
    }

    public void setCustomerFirstName(String customerFirstName) {
        this.customerFirstName = customerFirstName;
    }

    public String getCustomerLastName() {
        return customerLastName;
    }

    public void setCustomerLastName(String customerLastName) {
        this.customerLastName = customerLastName;
    }

    public String getCustomerEmail() {
        return customerEmail;
    }

    public void setCustomerEmail(String customerEmail) {
        this.customerEmail = customerEmail;
    }

    public long getCustomerPhoneNumber() {
        return customerPhoneNumber;
    }

    public void setCustomerPhoneNumber(long customerPhoneNumber) {
        this.customerPhoneNumber = customerPhoneNumber;
    }
}
