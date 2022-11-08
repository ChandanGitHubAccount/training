package dummy.Repository;

import dummy.Model.DummyStd;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StdRepository extends JpaRepository<DummyStd,Long> {
}
