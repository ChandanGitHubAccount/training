package dummy1.Service;

import dummy1.Model.Student;
import dummy1.StudentRepository.StdRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.NoSuchElementException;
import java.util.Optional;

@Service
public class StdService {
    @Autowired
    private StdRepo stdRepo;
    private static final String filePath = "C:\\Users\\Chandan H U\\Desktop\\JpaPic";

    public Student addStd(int stdId, String stdName, MultipartFile file) throws IOException {

        try {
            Student student = new Student();
            student.setStdId(stdId);
            student.setStdName(stdName);
            student.setFileName(file.getOriginalFilename());
            student.setPhotoType(file.getContentType());
            student.setStudentPhotoPath(filePath + File.separator + file.getOriginalFilename());

            file.transferTo(new File(filePath + File.separator + file.getOriginalFilename()));

            return stdRepo.save(student);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    public byte[] getStudentPhoto(long stdId) throws IOException {
        Optional<Student> student;
        try {
            student = stdRepo.findById(stdId);
        } catch (Exception exception) {
            throw new NoSuchElementException("Student Id " + stdId + " does not exits");
        }
        String path = student.get().getStudentPhotoPath();
        return Files.readAllBytes(Path.of(path));
    }

    public Student getStudentData(long stdId) {
        try{
            return stdRepo.findById(stdId).get();
        }catch (Exception exception) {
            throw new NoSuchElementException("Student Id " + stdId + " does not exits");
        }
    }
}
