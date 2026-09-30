package org.itmo.fuzzing.lab1;


import java.time.Duration;
import java.time.Instant;

import org.itmo.fuzzing.lect2.FunctionRunner;
import org.itmo.fuzzing.lect3.AFLFastSchedule;
import org.itmo.fuzzing.lect3.AdvancedMutationFuzzer;
import org.itmo.fuzzing.lect3.CountingGreyboxFuzzer;
import org.itmo.fuzzing.lect3.GreyBoxFuzzer;
import org.itmo.fuzzing.lect3.PowerSchedule;
import org.itmo.fuzzing.lect3.Seed;

import io.vavr.collection.List;

/**
 * Точка входа первой лабораторной работы: поиск входа, для которого
 * {@link MazeGenerated#maze(String)} возвращает {@code SOLVED}.
 *
 * <p>Выполняйте работу последовательно. Все варианты должны использовать одинаковые начальные
 * сиды, {@link MazeMutator мутатор} и бюджет запусков. Отличаться должен только способ использования
 * обратной связи.</p>
 *
 * <h2>Что использовать из лекции 3</h2>
 * <p>Не переписывайте общий цикл mutation-based и greybox-фаззинга. Используйте и расширяйте
 * готовые классы из пакета {@code org.itmo.fuzzing.lect3}:</p>
 * <ul>
 *     <li>{@link AdvancedMutationFuzzer} — основа dumb black-box режима: генерация кандидата из
 *     начальных сидов и мутации без использования покрытия при пополнении corpus;</li>
 *     <li>{@link GreyBoxFuzzer} вместе с {@link PowerSchedule} — основа coverage-guided режима:
 *     сохранение входов, которые открыли новое покрытие, и выбор сида из corpus;</li>
 *     <li>{@link GreyBoxFuzzer} вместе с собственной стратегией, наследующей
 *     {@link PowerSchedule}, — основа directed-режима: энергия сида должна зависеть от расстояния
 *     до целевого метода;</li>
 *     <li>{@link Seed} — готовая модель сида с данными, покрытием, расстоянием и энергией;</li>
 *     <li>{@link CountingGreyboxFuzzer} и {@link AFLFastSchedule} — примеры того, как расширять
 *     greybox-фаззер, учитывать статистику путей и переопределять расчёт энергии;</li>
 *     <li>{@link FunctionRunner} — готовый адаптер для запуска целевой функции и получения
 *     покрытия; используйте его с {@code MazeGenerated::maze}.</li>
 * </ul>
 *
 * <h2>Этап 1. Dumb black-box</h2>
 * <ol>
 *     <li>Создайте {@link AdvancedMutationFuzzer} с начальным сидом, например {@code "D"}, и
 *     экземпляром {@link MazeMutator}.</li>
 *     <li>Мутируйте вход и запускайте целевую функцию.</li>
 *     <li>Не используйте покрытие, call graph или расстояния до цели.</li>
 *     <li>Остановитесь при {@code SOLVED} либо после исчерпания бюджета.</li>
 * </ol>
 *
 * <h2>Этап 2. Coverage-guided fuzzing</h2>
 * <ol>
 *     <li>Используйте {@link GreyBoxFuzzer}, {@link PowerSchedule} и тот же {@link MazeMutator}.</li>
 *     <li>Собирайте покрытие каждого запуска через выданную instrumentation-инфраструктуру.</li>
 *     <li>Добавляйте вход в corpus, только если он открыл новое покрытие.</li>
 *     <li>Выбирайте сиды из corpus без знания положения целевой клетки.</li>
 * </ol>
 *
 * <h2>Этап 3. Directed greybox fuzzing</h2>
 * <ol>
 *     <li>Дополните ASM-инструментацию сбором рёбер {@code caller -> callee}.</li>
 *     <li>Постройте call graph методов {@code tile_*} и вычислите кратчайшие расстояния до метода,
 *     имя которого возвращает {@link MazeGenerated#targetTile()}.</li>
 *     <li>Определите расстояние {@link Seed} до цели по покрытым им методам.</li>
 *     <li>Реализуйте собственную стратегию {@link PowerSchedule}, назначающую больше энергии
 *     сидам с меньшим расстоянием до цели.</li>
 * </ol>
 *
 * <h2>Что выдано</h2>
 * <ul>
 *     <li>целевая функция {@link MazeGenerated#maze(String)} и генератор лабиринта;</li>
 *     <li>{@link FunctionRunner} и instrumentation-инфраструктура сбора покрытия;</li>
 *     <li>общий цикл фаззинга, corpus, модель сида и базовые стратегии из лекции 3;</li>
 *     <li>контракты {@link MazeMutator} и этой точки входа.</li>
 * </ul>
 *
 * <h2>Что требуется реализовать</h2>
 * <ul>
 *     <li>операции {@link MazeMutator} для алфавита {@code L/R/U/D};</li>
 *     <li>конфигурацию и запуск трёх режимов на выданном каркасе;</li>
 *     <li>сбор рёбер call graph в ASM-инструментации;</li>
 *     <li>расчёт расстояний от методов до {@link MazeGenerated#targetTile()};</li>
 *     <li>расстояние сида и directed-стратегию назначения энергии;</li>
 *     <li>сбор и сравнение результатов эксперимента.</li>
 * </ul>
 *
 * <h2>Сравнение</h2>
 * <p>Для каждого режима проведите несколько запусков и сравните долю успешных запусков,
 * медианное число выполнений цели до {@code SOLVED} и время. Не включайте заранее известный
 * маршрут в начальный corpus.</p>
 */
public final class MazeFuzzer {
    private static final int MAX_ITERS = 1_000_000;
    private static final Duration MAX_DURATION = Duration.ofSeconds(3);
    private static final int RUNS_PER_TYPE = 10;

    private MazeFuzzer() {
    }

    record Stats(Boolean success, int attempts, Duration time) {
    };

    public static void main(final String[] args) {
      System.out.println("running black box");
      final var bb = List.fill(RUNS_PER_TYPE, () -> black_box());
      System.out.println("running coverage based");
      final var cov = List.fill(RUNS_PER_TYPE, () -> coverage_guided());
      System.out.println("running directed stats");
      final var dir = List.fill(RUNS_PER_TYPE, () -> directed());

      System.out.println("Black box");
      bb.forEach(MazeFuzzer::print_stats);
      System.out.println("Coverage based");
      cov.forEach(MazeFuzzer::print_stats);
      System.out.println("Directed stats");
      dir.forEach(MazeFuzzer::print_stats);
      summary("Black", bb);
      summary("Coverage", cov);
      summary("Directed", dir);
    }

    private static void summary(final String mode, final List<Stats> runs) {
      final var ok = runs.filter(Stats::success);
      System.out.printf("%s: success %d/%d, median attempts %s, avg %s ms%n",
          mode, ok.size(), runs.size(),
          median(runs.map(s -> (double) s.attempts())),
          avg(runs.map(s -> (double) s.time().toMillis())));
    }

    private static String avg(final List<Double> xs) {
      if (xs.isEmpty())
        return "n/a";
      return Integer.toString(xs.sum().intValue() / xs.length());
    }

    private static String median(final List<Double> xs) {
      if (xs.isEmpty()) {
        return "n/a";
      }

      final var sorted = xs.sorted();
      final int n = sorted.length();

      return String.format(
          "%.1f",
          (sorted.get((n - 1) / 2) + sorted.get(n / 2)) / 2.0);
    }

    private static final void print_stats(final Stats stats) {
      System.out.println("OK: " + stats.success + "; attempts: " + stats.attempts + "; time: " + stats.time);
    }


    private static final Duration timed(final Instant start) {
      return Duration.between(start, Instant.now());
    }
    
    private static final Stats run_fuzzing(final AdvancedMutationFuzzer fuzzer) {
      final var start = Instant.now();
      final var runner = new FunctionRunner(MazeGenerated::maze);

      int i = 0;
      for (; i < MAX_ITERS && timed(start).compareTo(MAX_DURATION) < 0; ++i) {
        final String value = fuzzer.fuzz();

        final String res = (String) (fuzzer.run(runner, value));

        if (res.contains("SOLVED")) {
          return new Stats(true, i+1, timed(start));
        }
      }
      return new Stats(false, i, timed(start));
    }


    private static final Stats black_box() {
      final var fuzzer = new AdvancedMutationFuzzer(
          List.of("D").asJava(),
          new MazeMutator(),
          new PowerSchedule(),
          1, 30);
      return run_fuzzing(fuzzer);
    }

    private static final Stats coverage_guided() {
      final var fuzzer = new GreyBoxFuzzer(
          List.of("D").asJava(),
          new MazeMutator(),
          new PowerSchedule(),
          1, 1);
      return run_fuzzing(fuzzer);
    }

    private static final Stats directed() {
      final var fuzzer = new GreyBoxFuzzer(
          List.of("D").asJava(),
          new MazeMutator(),
          new DirectedSchedule(),
          1, 1);
      return run_fuzzing(fuzzer);
    }
}
