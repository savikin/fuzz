package org.itmo.fuzzing.lect2.instrumentation;

import java.util.HashMap;
import java.util.HashSet;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

public class CoverageTracker {

    public static final ConcurrentSkipListSet<String> coverage = new ConcurrentSkipListSet<String>();
    public static final ConcurrentSkipListSet<String> fullCoverage = new ConcurrentSkipListSet<String>();
    public static final ConcurrentHashMap<String, Set<String>> call_graph = new ConcurrentHashMap<>();
    public static final ConcurrentHashMap<String, Integer> target_distance = new ConcurrentHashMap<>();

    public static void logCoverage(String methodSignature, String lineNumber) {
        coverage.add(methodSignature + ":" + lineNumber);
    }

    public static void logFullCoverage(String methodSignature, String lineNumber) {
        fullCoverage.add(methodSignature + ":" + lineNumber);
    }

    public static void logStaticEdge(String caller, String callee) {
      if (caller.startsWith("tile_") && callee.startsWith("tile_")) {
        call_graph.computeIfAbsent(caller, _ -> ConcurrentHashMap.newKeySet()).add(callee);
      }
    }

    public static record Dist(Integer distance, String tile) implements Comparable<Dist> {
      @Override
      public int compareTo(Dist other) {
        if (other.distance != this.distance)
          return this.distance.compareTo(other.distance);
        return this.tile.compareTo(other.tile);
      }
    }

    public static final synchronized void calculate_path() {
      final var q = new PriorityQueue<Dist>();
      q.add(new Dist(0, "tile_5_7"));

      final HashMap<String, HashSet<String>> r_call_graph = new HashMap<>();
      for (final var i : call_graph.entrySet()) {
        final var from = i.getKey();
        for (final var to : i.getValue()) {
          r_call_graph.computeIfAbsent(to, _ -> new HashSet<String>()).add(from);
        }
      }

      int lastMax = 0;
      while (!q.isEmpty()) {
        final var value = q.poll();
        if (lastMax > value.distance) {
          System.out.println("BFS error");
          System.err.println("BFS error");
          System.exit(1);
        }

        lastMax = value.distance;
        target_distance.put(value.tile, value.distance);
        r_call_graph.get(value.tile).forEach(y -> {
          if (!target_distance.containsKey(y)) {
            q.add(new Dist(value.distance + 1, y));
          }
        });
      }
    }

    /**
     * Возвращает непокрытые строки для указанного метода
     * @param methodName имя метода
     * @return множество непокрытых строк в формате "methodName:lineNumber"
     */
    public static Set<String> getDiffFor(String methodName) {
        Set<String> result = new TreeSet<>();

        // Получаем все строки метода из fullCoverage
        for (String entry : fullCoverage) {
            if (entry.startsWith(methodName + ":")) {
                // Если эта строка не покрыта, добавляем в результат
                if (!coverage.contains(entry)) {
                    result.add(entry);
                }
            }
        }

        return result;
    }

    // Дополнительные полезные методы:

    /**
     * Возвращает процент покрытия для указанного метода
     */
    public static double getCoveragePercentageFor(String methodName) {
        int totalLines = 0;
        int coveredLines = 0;

        for (String entry : fullCoverage) {
            if (entry.startsWith(methodName + ":")) {
                totalLines++;
                if (coverage.contains(entry)) {
                    coveredLines++;
                }
            }
        }

        return totalLines == 0 ? 100.0 : (coveredLines * 100.0) / totalLines;
    }

    /**
     * Возвращает только номера непокрытых строк для метода
     */
    public static Set<Integer> getUncoveredLineNumbersFor(String methodName) {
        Set<Integer> result = new TreeSet<>();

        for (String entry : fullCoverage) {
            if (entry.startsWith(methodName + ":")) {
                if (!coverage.contains(entry)) {
                    String lineNumber = entry.substring(entry.indexOf(':') + 1);
                    result.add(Integer.parseInt(lineNumber));
                }
            }
        }

        return result;
    }

    /**
     * Возвращает общую статистику покрытия
     */
    public static String getCoverageStats() {
        int covered = coverage.size();
        int total = fullCoverage.size();
        double percentage = total == 0 ? 100.0 : (covered * 100.0) / total;

        return String.format("Coverage: %d/%d (%.2f%%)", covered, total, percentage);
    }

    /**
     * Возвращает статистику покрытия для конкретного метода
     */
    public static String getCoverageStatsFor(String methodName) {
        int totalLines = 0;
        int coveredLines = 0;

        for (String entry : fullCoverage) {
            if (entry.startsWith(methodName + ":")) {
                totalLines++;
                if (coverage.contains(entry)) {
                    coveredLines++;
                }
            }
        }

        double percentage = totalLines == 0 ? 100.0 : (coveredLines * 100.0) / totalLines;
        return String.format("Coverage for %s: %d/%d (%.2f%%)",
                methodName, coveredLines, totalLines, percentage);
    }
}
