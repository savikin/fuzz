package org.itmo.fuzzing.lab1;

import java.util.List;

import org.itmo.fuzzing.lect2.instrumentation.CoverageTracker;
import org.itmo.fuzzing.lect3.PowerSchedule;
import org.itmo.fuzzing.lect3.Seed;

public final class DirectedSchedule extends PowerSchedule {
  private static final double seed_distance(Seed seed) {
    double res = Double.MAX_VALUE;
    for (var i : seed.getCoverage()) {
      res = Math.min(res, CoverageTracker.target_distance.getOrDefault(i.getFunction(), Integer.MAX_VALUE));
    }
    return res;
  }

  @Override
  public void assignEnergy(List<Seed> population) {
    for (var i : population) {
      var dist = seed_distance(i);
      i.setDistance(dist);
      i.setEnergy(Math.pow(0.5, dist));
    }
  }
}
