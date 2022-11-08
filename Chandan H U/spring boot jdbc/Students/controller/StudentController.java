package example.Students.controller;

import example.Students.Model.Studentinfo;
import example.Students.Service.StudentInterfaces;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
public class StudentController {
    @Autowired
    StudentInterfaces studentInterfaces;

    @PostMapping("/addStudentDetails:")
    public void addStudentDetails(@RequestBody Studentinfo studentinfo) {
        try{
            studentInterfaces.addStudentDetails(studentinfo);
        }catch (Exception exception){
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/viewAllStudentDetails:")
    public ResponseEntity<List<Studentinfo>> DisplayAllRecordsOfStudent() {
        try{
            return ResponseEntity.of(Optional.of(studentInterfaces.displayStudentDetail()));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @DeleteMapping("/deleteStudentDetails/{studentUSN}")
    public void deleteStudentRecordByEmployeeId(@PathVariable String studentUSN) {
        try {
            studentInterfaces.deleteParticularStudentsRecord(studentUSN);
        }catch (Exception exception){
            ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @PutMapping("/updateStudentMobileNumber/{studentUSN}")
    public void updateEmployeeDetails(@PathVariable String studentUSN, @RequestBody long studentMobileNumber) {
        try{
            studentInterfaces.updateStudentMobileNumber(studentUSN, studentMobileNumber);
        }catch (Exception exception){
            ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

}
