import { describe, it, expect } from "vitest";
import moment from "moment";
import { countBusinessDays } from "../Routes/EmployeeRoute";

describe("countBusinessDays", () => {
  it("should return 6 for a full week Monday to Friday", () => {
    const startDate = moment("2024-09-09"); //Lundi
    const endDate = moment("2024-09-13"); //Vendredi

    const result = countBusinessDays(startDate, endDate);

    expect(result).toBe(6);
  });

  it("should return 12 for two weeks with week end", () => {
    const startDate = moment("2024-09-09"); //Lundi
    const endDate = moment("2024-09-20"); //Vendredi

    const result = countBusinessDays(startDate, endDate);

    expect(result).toBe(12);
  });

  it("should return 1 for the same date", () => {
    const startDate = moment("2024-09-09"); //Lundi
    const endDate = moment("2024-09-09"); //Vendredi

    const result = countBusinessDays(startDate, endDate);

    expect(result).toBe(1);
  });
});
