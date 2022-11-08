package dummy1.Controller;

import dummy1.Model.Student;
import dummy1.Service.StdService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.NoSuchElementException;
import java.util.Optional;

@RestController
@RequestMapping("/student")
public class StdController {
    @Autowired
    private StdService stdService;

    @PostMapping("/add")
    public Student addStdDetail(@RequestParam("studentId") int studentId, @RequestParam("studentName") String studentName, @RequestParam("file") MultipartFile file) throws Exception {
        try {
            return stdService.addStd(studentId, studentName, file);
        } catch (Exception exception) {
            throw new Exception("Not Exist");
        }
    }

    @GetMapping("/photo")
    public ResponseEntity<?> getStudentPhoto(@RequestParam("stdId") long stdId) {
        byte[] image;
        try {
            image = stdService.getStudentPhoto(stdId);
            return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.valueOf("image/png")).body(image);
        } catch (Exception exception) {
            throw new NoSuchElementException("Student Id " + stdId + " does not exits");
        }

    }

    @GetMapping("/get/data")
    public ResponseEntity<Student> getStudentData(@RequestParam("stdId") long stdId){
        try{
            return ResponseEntity.of(Optional.of(stdService.getStudentData(stdId)));
        } catch (Exception exception) {
            throw new NoSuchElementException("Student Id " + stdId + " does not exits");
        }
    }
}
