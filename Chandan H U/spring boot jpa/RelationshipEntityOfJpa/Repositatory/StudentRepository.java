package RelationshipEntityOfJpa.Repositatory;

import RelationshipEntityOfJpa.Model.Students;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StudentRepository extends JpaRepository<Students, String > {
}
