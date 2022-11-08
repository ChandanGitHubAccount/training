package dummy1.StudentRepository;

import dummy1.Model.Student;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StdRepo extends JpaRepository<Student, Long> {
}
