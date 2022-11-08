package ManyToMany.Projects.ProjectRepository;

import ManyToMany.Projects.Model.Projects;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProjectRepository extends JpaRepository<Projects,Long> {
}
