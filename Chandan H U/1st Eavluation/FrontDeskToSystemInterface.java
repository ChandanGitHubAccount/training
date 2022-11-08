package FirstEavluation;

import java.util.Map;

public interface FrontDeskToSystemInterface {
    void bookTicket(Map<String, RegisteredCustomersDetails> customersDetails);
    void cancelTicket(String customerId, Map<String, City> city, Map<String, RegisteredCustomersDetails> customersDetails);
    void SendNotifications(Map<String, RegisteredCustomersDetails> customersDetails);
}
