package secondmajorevalustion.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import secondmajorevalustion.model.WaitingTicket;

public interface WaitingRepository extends JpaRepository<WaitingTicket,Integer> {
}
