package example.templets.Services;

import example.templets.Model.RestTemplateEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class RestTemplateService {

    /*@Autowired
    private RestTemplate restTemplate;

    public String addObject(RestTemplateEntity restTemplateEntity) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Object> entity = new HttpEntity<>(restTemplateEntity, httpHeaders);
        return restTemplate.exchange("http://localhost:8080/add", HttpMethod.POST, entity, String.class).getBody();
    }
*/

}
