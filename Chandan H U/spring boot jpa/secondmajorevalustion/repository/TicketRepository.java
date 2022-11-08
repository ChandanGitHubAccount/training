package secondmajorevalustion.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import secondmajorevalustion.model.TicketDetails;

public interface TicketRepository extends JpaRepository<TicketDetails,Integer> {
}
