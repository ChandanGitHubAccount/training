package ManyToMany.Projects.Controller;

import ManyToMany.Projects.Model.Projects;
import ManyToMany.Projects.Service.ProjectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
public class ProjectController {
  @Autowired
   private ProjectService projectService;

  @PostMapping("/addProjects")
    public ResponseEntity<Projects> addProjects(@RequestBody Projects projects){
      try {
          return ResponseEntity.of(Optional.of(projectService.addProjects(projects)));
      }catch (Exception exception){
          return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
      }
  }

  @GetMapping("/getAllProjects")
    public ResponseEntity<List<Projects>> getAllProjects(){
      try {
          return ResponseEntity.of(Optional.of(projectService.getAllProjectDetails()));
      }catch (Exception exception){
          return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
      }
  }
}
