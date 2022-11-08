package ExampleOfJPA.Service;

import ExampleOfJPA.Model.EmployeeData;
import ExampleOfJPA.Repositary.EmployeeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class EmployeeService implements EmployeeInterface {
    @Autowired
    EmployeeRepository employeeRepository;

    //constructor
    @PostConstruct
    public void constructEmployeeData() {
        List<EmployeeData> employeeData = new ArrayList<>();
        employeeData.add(new EmployeeData(10001L, "Chandan", LocalDate.of(2000,5,2), 22,
                "Male", "IT", 8050514428L, "Hassan"));
        employeeData.add(new EmployeeData(10002L, "Vila", LocalDate.of(1999,6,12), 23,
                "Male", "CIVIL", 6802365478L, "Kar war"));
        employeeData.add(new EmployeeData(10003L, "Namratha",LocalDate.of(2000,12,21), 22,
                "Female", "IT", 9856321478L, "Sakaleshpura"));
        employeeData.add(new EmployeeData(10004L, "Vino",LocalDate.of(2001,1,18), 22,
                "Female", "GOVT", 9630258741L, "Belur"));
        employeeRepository.saveAll(employeeData);
    }

    //Interface method
    @Override
    public Optional<EmployeeData> findAllRecordsById(long employeeId) {
        try {
            return employeeRepository.findById(employeeId);
        } catch (Exception exception) {
            exception.printStackTrace();
            return Optional.empty();
        }
    }

    @Override
    public EmployeeData addEmployeeDetails(EmployeeData employeeData) {
        try {
            return employeeRepository.save(employeeData);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    //By using JPA Repository
    public List<EmployeeData> findAllEmployeeDetails() {
        try {
            return employeeRepository.findAll();
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    public List<EmployeeData> findEmployeeByProfession(String employeeProfession) {
        try {
            return employeeRepository.findByEmployeeProfession(employeeProfession);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    public Optional<EmployeeData> deleteEmployeeById(long employeeId) {
        try {
            Optional<EmployeeData> employeeData = employeeRepository.findByEmployeeId(employeeId);
            employeeRepository.deleteByEmployeeId(employeeId);
            return employeeData;
        } catch (Exception exception) {
            exception.printStackTrace();
            return Optional.empty();
        }
    }

    public List<EmployeeData> findEmployeeByProfessionAndAge(String employeeProfession, int employeeAge) {
        try {
            return employeeRepository.findByEmployeeProfessionAndEmployeeAge(employeeProfession, employeeAge);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    public List<EmployeeData> findEmployeeByProfessionByIgnoreCase(String employeeProfession) {
        try {
            return employeeRepository.findByEmployeeProfessionIgnoreCase(employeeProfession);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    public long countEmployeeOfSameAge(int employeeAge) {
        try {
            return employeeRepository.countByEmployeeAge(employeeAge);
        } catch (Exception exception) {
            exception.printStackTrace();
            return 0L;
        }
    }

    //Custom Query
    public EmployeeData findByCustomQuery(long employeeId) {
        try {
            return employeeRepository.getUsersCustomQuery(employeeId);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    //Sorting
    public List<EmployeeData> sortEmployeeByField(String field) {
        try {
            return employeeRepository.findAll(Sort.by(Sort.Direction.ASC, field));
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    public List<EmployeeData> sortEmployeeByFieldByDescending(String field) {
        try {
            return employeeRepository.findAll(Sort.by(Sort.Direction.DESC, field));
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    //Pagination With sorting
    public Page<EmployeeData> findEmployeeByPaging(int startIndex, int endIndex) {
        try {
            return employeeRepository.findAll(PageRequest.of(startIndex, endIndex, Sort.Direction.ASC));
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }
}
