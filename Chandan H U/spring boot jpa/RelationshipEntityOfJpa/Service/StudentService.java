package RelationshipEntityOfJpa.Service;

import RelationshipEntityOfJpa.Model.Students;
import RelationshipEntityOfJpa.Repositatory.StudentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class StudentService {
    @Autowired
    private StudentRepository studentRepository;

    public Students addStudentDetails(Students student) {
        try {
            return studentRepository.save(student);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    public List<Students> getAllStudentDetails() {
        try {
            return studentRepository.findAll();
        } catch (Exception exception) {
            return null;
        }
    }
}
