package edu.uwm.capstone.controller;

import edu.uwm.capstone.db.JudgeDao;
import edu.uwm.capstone.db.PosterDao;
import edu.uwm.capstone.db.ScoreDao;
import edu.uwm.capstone.model.Judge.Judge;
import edu.uwm.capstone.model.Poster.Poster;
import edu.uwm.capstone.model.Score.Score;
import edu.uwm.capstone.sql.exception.DaoException;
import edu.uwm.capstone.util.TestDataUtility;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static edu.uwm.capstone.util.TestDataUtility.*;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * This test class uses Mockito framework to mock out all of the dependencies for the class under test and isolate it from the rest of the application.
 * This way the test suite verifies if the class under test works correctly assuming all of its dependencies are behaving as expected.
 */
@RunWith(MockitoJUnitRunner.class)
public class ScoreRestControllerUnitTest{
    @Mock
    private ScoreDao scoreDao;

    @Mock
    private PosterDao posterDao;

    @Mock
    private JudgeDao judgeDao;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private ScoreRestController scoreRestController;


    private static final String TEST_ERROR_MESSAGE = randomAlphabetic(15);

    @Test
    public void create() throws IOException {
        Score scoreToCreate = scoreWithTestValues();
        when(scoreDao.create(any(Score.class))).thenReturn(scoreToCreate);

        Score createdScore = scoreRestController.create(scoreToCreate, response);
        assertEquals(scoreToCreate, createdScore);
    }

    @Test
    public void createNull() throws IOException{
        scoreRestController.create(null,response);
        verify(response, times(1)).sendError(HttpServletResponse.SC_PRECONDITION_FAILED,"Received null Score object");
    }

    @Test
    public void createException() throws IOException{
        Score scoreToCreate = scoreWithTestValues();
        when(scoreDao.create(any(Score.class))).thenThrow(new DaoException(TEST_ERROR_MESSAGE));

        scoreRestController.create(scoreToCreate,response);
        verify(response,times(1)).sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, TEST_ERROR_MESSAGE);
    }

    @Test
    public void GenerateRoundTwoAssignments() throws IOException{
        List<String> posters = new ArrayList<>();
        Poster poster1 = posterWithTestValues();
        posters.add(poster1.getPoster_id());
        when(posterDao.read(anyString())).thenReturn(poster1);

        List<Judge> judges = new ArrayList<>();
        Judge judge1 = TestDataUtility.judgeWithTestValues();
        judges.add(judge1);
        when(judgeDao.readAllJudges(poster1.getStatus())).thenReturn(judges);

        Score score = scoreWithTestValues();
        when(scoreDao.create(any(Score.class))).thenReturn(score);

        scoreRestController.GenerateRoundTwoAssignments(posters,response);

        //assertEquals(score.getPoster_id(),poster1.getPoster_id());
        //assertEquals(score.getJudge_id(),judge1.getJudge_id());

    }

    @Test
    public void GenerateRoundTwoAssignmentsException() throws IOException{
        List<String> posters = new ArrayList<>();
        Score score = scoreWithTestValues();
        Poster poster = posterWithTestValues();
        posters.add(poster.getPoster_id());
        //when(posterDao.read(anyString())).thenReturn(poster);
        //doThrow(new DaoException(TEST_ERROR_MESSAGE)).when(posterDao).read(anyString());
        //scoreRestController.GenerateRoundTwoAssignments(posters,response);
//        verify(response,times(1)).sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, TEST_ERROR_MESSAGE);

    }

}