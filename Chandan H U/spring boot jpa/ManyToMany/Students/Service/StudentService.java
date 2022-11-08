package ManyToMany.Students.Service;

import ManyToMany.Students.StudentRepository.StudentRepository;
import ManyToMany.Students.model.Students;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class StudentService {
    @Autowired
    private StudentRepository studentRepository;

    public Students addStudents(Students Students){
        try{
            return studentRepository.save(Students);
        }catch (Exception exception){
            exception.printStackTrace();
            return null;
        }
    }

    public List<Students> getAllStudentDetails(){
        try {
            return studentRepository.findAll();
        }catch (Exception exception){
            exception.printStackTrace();
            return null;
        }
    }
}
