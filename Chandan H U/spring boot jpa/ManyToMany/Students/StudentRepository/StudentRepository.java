package ManyToMany.Students.StudentRepository;

import ManyToMany.Students.model.Students;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StudentRepository extends JpaRepository<Students,Long> {
}
