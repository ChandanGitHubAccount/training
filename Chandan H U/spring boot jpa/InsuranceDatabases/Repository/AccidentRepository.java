package InsuranceDatabases.Repository;

import InsuranceDatabases.Model.Accident;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccidentRepository extends JpaRepository<Accident,Integer> {
}
