package ManyToMany.Students.Controller;

import ManyToMany.Projects.Model.Projects;
import ManyToMany.Students.Service.StudentService;
import ManyToMany.Students.model.Students;
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
public class StudentController {
    @Autowired
    private StudentService studentService;

    @PostMapping("/addStudents")
    public ResponseEntity<Students> addStudents(@RequestBody Students Students){
        try {
            return ResponseEntity.of(Optional.of(studentService.addStudents(Students)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/getAllStudents")
    public ResponseEntity<List<Students>> getAllProjects(){
        try {
            return ResponseEntity.of(Optional.of(studentService.getAllStudentDetails()));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}
