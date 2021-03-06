import Dependencies._

lazy val root = (project in file(".")).
  settings(
    inThisBuild(List(
      organization := "world.jawair",
      scalaVersion := "2.12.3",
      version      := "0.0.1-SNAPSHOT"
    )),
    name := "sencrypt",
    libraryDependencies += scalaTest % Test
  )
