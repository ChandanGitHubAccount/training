package ExampleOfJPA.Controller;

import ExampleOfJPA.Model.EmployeeData;
import ExampleOfJPA.Service.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/spring-jpa")
public class EmployeeController {
    @Autowired
    EmployeeService employeeService;

    @PostMapping("/addEmployeeDetails")
    public ResponseEntity<EmployeeData> addEmployeeDetails(@RequestBody EmployeeData employeeData) {
        try {
            return ResponseEntity.of(Optional.of(employeeService.addEmployeeDetails(employeeData)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        }
    }

    @GetMapping("/findAllRecordsById/{employeeId}")
    public ResponseEntity<Optional<EmployeeData>> findAllRecordsById(@PathVariable long employeeId) {
        try {
            return ResponseEntity.of(Optional.of(employeeService.findAllRecordsById(employeeId)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("/all")
    public ResponseEntity<List<EmployeeData>> findAllEmployeeData() {
        try {
            return ResponseEntity.of(Optional.of(employeeService.findAllEmployeeDetails()));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("/findEmployeeByProfession/{employeeProfession}")
    public ResponseEntity<List<EmployeeData>> findEmployeeByProfession(@PathVariable String employeeProfession) {
        try {
            return ResponseEntity.of(Optional.of(employeeService.findEmployeeByProfession(employeeProfession)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @DeleteMapping("/deleteEmployeeById/{employeeId}")
    public ResponseEntity<Optional<EmployeeData>> deleteEmployeeById(@PathVariable long employeeId) {
        try {
            return ResponseEntity.of(Optional.of(employeeService.deleteEmployeeById(employeeId)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/findEmployeeByProfessionAndAge/{employeeProfession}/{employeeAge}")
    public ResponseEntity<List<EmployeeData>> findEmployeeByProfessionAndAge(@PathVariable String employeeProfession, @PathVariable int employeeAge) {
        try {
            return ResponseEntity.of(Optional.of(employeeService.findEmployeeByProfessionAndAge(employeeProfession, employeeAge)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("/findEmployeeByProfessionByIgnoreCase/{employeeProfession}")
    public ResponseEntity<List<EmployeeData>> findEmployeeByProfessionByIgnoreCase(@PathVariable String employeeProfession) {
        try {
            return ResponseEntity.of(Optional.of(employeeService.findEmployeeByProfessionByIgnoreCase(employeeProfession)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    //uri = http://localhost:3306/spring-jpa/findByCustomQuery?employeeId={employeeId}
    @GetMapping("/findByCustomQuery")
    public ResponseEntity<EmployeeData> findByCustomQuery(@RequestParam("employeeId") long employeeId) {
        try {
            return ResponseEntity.of(Optional.of(employeeService.findByCustomQuery(employeeId)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/sortEmployeeByAscending/{field}")
    public ResponseEntity<List<EmployeeData>> sortEmployeeByAscending(@PathVariable String field) {
        try {
            return ResponseEntity.of(Optional.of(employeeService.sortEmployeeByField(field)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/sortEmployeeByDescending/{field}")
    public ResponseEntity<List<EmployeeData>> sortEmployeeByDescending(@PathVariable String field) {
        try {
            return ResponseEntity.of(Optional.of(employeeService.sortEmployeeByFieldByDescending(field)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/countEmployeeOfSameAge/{employeeAge}")
    public ResponseEntity<Long> countEmployeeOfSameAge(@PathVariable int employeeAge) {
        try {
            return ResponseEntity.of(Optional.of(employeeService.countEmployeeOfSameAge(employeeAge)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    //not done
    @GetMapping("/findEmployeeByPaging/{startIndex}/{endIndex}")
    public ResponseEntity<Page<EmployeeData>> findEmployeeByPaging(@PathVariable int startIndex, @PathVariable int endIndex) {
        try {
            return ResponseEntity.of(Optional.of(employeeService.findEmployeeByPaging(startIndex, endIndex)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }
}
