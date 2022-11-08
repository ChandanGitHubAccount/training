package ManyToMany.Projects.Service;

import ManyToMany.Projects.Model.Projects;
import ManyToMany.Projects.ProjectRepository.ProjectRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProjectService {
    @Autowired
    private ProjectRepository projectRepository;

    public Projects addProjects(Projects project){
        try{
            return projectRepository.save(project);
        }catch (Exception exception){
            exception.printStackTrace();
            return null;
        }
    }

    public List<Projects> getAllProjectDetails(){
        try {
            return projectRepository.findAll();
        }catch (Exception exception){
            exception.printStackTrace();
            return null;
        }
    }
}
