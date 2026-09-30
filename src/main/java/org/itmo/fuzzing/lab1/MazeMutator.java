package org.itmo.fuzzing.lab1;

import org.itmo.fuzzing.lect3.FuzzMutator;

/**
 * Мутатор маршрутов для {@link MazeGenerated#maze(String)}.
 *
 * <p>Класс наследует {@link FuzzMutator}, поэтому экземпляр {@code MazeMutator} можно напрямую
 * передавать фаззерам из пакета {@code org.itmo.fuzzing.lect3}. Готовый {@code FuzzMutator}
 * использовать без адаптации нельзя: он генерирует произвольные печатные символы, тогда как
 * маршрут лабиринта должен состоять только из {@code L}, {@code R}, {@code U} и {@code D}.</p>
 *
 * <p>Реализуйте четыре мутации:</p>
 * <ul>
 *     <li>{@link #append(String)} — добавить случайный ход в конец;</li>
 *     <li>{@link #insert(String)} — вставить случайный ход в случайную позицию;</li>
 *     <li>{@link #replace(String)} — заменить случайный существующий ход;</li>
 *     <li>{@link #delete(String)} — удалить случайный существующий ход.</li>
 * </ul>
 *
 * <p>{@link #mutate(String)} должен случайно выбирать одну из этих операций. Один и тот же
 * экземпляр мутационной стратегии необходимо использовать в dumb black-box, coverage-guided и
 * directed конфигурациях: иначе результаты экспериментов будут несопоставимы.</p>
 *
 * <h2>Граничные случаи</h2>
 * <ul>
 *     <li>Мутации не должны падать на пустой строке.</li>
 *     <li>Для пустой строки {@code replace} может работать как {@code append}, а {@code delete}
 *     должен вернуть пустую строку.</li>
 *     <li>Результат не должен быть длиннее {@link #maxLength}; при достижении лимита выбирайте
 *     операцию, которая не увеличивает строку.</li>
 *     <li>Конструктор должен отклонять некорректное ограничение длины через
 *     {@link IllegalArgumentException}.</li>
 * </ul>
 */
public final class MazeMutator extends FuzzMutator {

    public static final String ALPHABET = "LRUD";
    public static final int DEFAULT_MAX_LENGTH = 64;

    private final int maxLength;

    /**
     * Создаёт мутатор с ограничением длины {@link #DEFAULT_MAX_LENGTH}.
     */
    public MazeMutator() {
        this(DEFAULT_MAX_LENGTH);
    }

    /**
     * Создаёт мутатор с заданным ограничением длины маршрута.
     *
     * @param maxLength максимальная допустимая длина результата
     */
    public MazeMutator(final int maxLength) {
      if (maxLength <= 0) {
        throw new IllegalArgumentException("Meaningless maxLength in MazeMutator");
      }
      this.maxLength = maxLength;
    }

    /**
     * Выполняет одну случайную мутацию маршрута.
     *
     * @param input исходный маршрут
     * @return мутированный маршрут из символов {@link #ALPHABET}, не длиннее {@link #maxLength}
     */
    @Override
    public String mutate(final String input) {
      switch (this.random.nextInt() & 3) {
        case 0:
          return this.append(input);
        case 1:
          return this.insert(input);
        case 2:
          return this.replace(input);
        case 3:
          return this.delete(input);
      }
      throw new IllegalStateException("O_O HOW DID YOU DO THAT???!!!");
    }

    private final char random_move() {
      return ALPHABET.charAt(random.nextInt() & 3);
    }

    private final int random_pos(String input) {
      return random.nextInt(input.length());
    }

    private final void validate(String input) {
      if (input.length() > maxLength) {
        throw new IllegalStateException("ILLEGAL MUTATOR STATE");
      }
    }

    /**
     * Добавляет случайный символ из {@link #ALPHABET} в конец строки, не превышая
     * {@link #maxLength}.
     */
    public String append(final String input) {
      validate(input);
      if (input.length() < maxLength) {
        return input + random_move();
      }
      return replace(input);
    }

    /**
     * Вставляет случайный символ из {@link #ALPHABET} в случайную позицию, не превышая
     * {@link #maxLength}.
     */
    public String insert(final String input) {
      validate(input);
      if (input.isEmpty()) {
        return append(input);
      } else if (input.length() < maxLength) {
        final var ret = new StringBuilder(input);

        ret.insert(random_pos(input), random_move());
        return ret.toString();
      }
      return replace(input);
    }

    /**
     * Заменяет случайный символ маршрута на символ из {@link #ALPHABET}.
     */
    public String replace(final String input) {
      validate(input);
      if (input.isEmpty()) {
        return append(input);
      }
      final var ret = new StringBuilder(input);

      ret.setCharAt(random_pos(input), random_move());
      return ret.toString();
    }

    /**
     * Удаляет случайный символ маршрута; для пустой строки возвращает пустую строку.
     */
    public String delete(final String input) {
      validate(input);
      if (input.isEmpty()) {
        return "";
      }
      final var ret = new StringBuilder(input);

      ret.deleteCharAt(random_pos(input));
      return ret.toString();
    }
}
