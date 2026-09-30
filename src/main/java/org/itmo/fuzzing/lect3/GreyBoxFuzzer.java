package org.itmo.fuzzing.lect3;

import org.itmo.fuzzing.lect2.FunctionRunner;
import org.itmo.fuzzing.util.SetUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

public class GreyBoxFuzzer extends AdvancedMutationFuzzer {
    /**
     * Constructor.
     *
     * @param seeds        - a list of (input) strings to mutate.
     * @param mutator      - the mutator to apply.
     * @param schedule     - the power schedule to apply.
     * @param minMutations
     * @param maxMutations
     */
    public GreyBoxFuzzer(List<String> seeds, FuzzMutator mutator, PowerSchedule schedule, int minMutations, int maxMutations) {
        super(seeds, mutator, schedule, minMutations, maxMutations);
    }

    @Override
    public void reset() {
        super.reset();
        coveragesSeen = new HashSet<>();
        population = new ArrayList<>();
    }

    @Override
    public Object run(FunctionRunner runner, String input) {
        FunctionRunner.Tuple<Object, String> resultOutcome = runner.run(input);
        Object result = resultOutcome.first;
        if (!SetUtils.diff(runner.coverage, coveragesSeen).isEmpty()) {
            //System.out.println("NEW COVERAGE");
            //System.out.println("INPUT = " + input);
            // Adding seed to population
            Seed s = new Seed(input);
            s.coverage.addAll(runner.coverage.stream()
                    .map(Location::buildFromString)
                    .collect(Collectors.toSet()));
//            s.coverage.addAll(runner.coverage.stream().map(Location::buildFromString).toList());
            population.add(s);
            coveragesSeen.addAll(runner.coverage);
        }
        return result;
    }
}
