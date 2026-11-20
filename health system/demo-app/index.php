<?php
declare(strict_types=1);

$demo = require __DIR__ . '/demo-data.php';
$student = $demo['student'];
$courses = $demo['courses'];
$assignments = $demo['assignments'];
$activity = $demo['activity'];
$e = fn($value) => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#f4f6fb">
    <title>My learning | GradeGenius</title>
    <style>
        :root {
            color-scheme: light;
            --page: #f4f6fb;
            --surface: #fff;
            --ink: #1c2540;
            --muted: #737d96;
            --line: #e7eaf2;
            --accent: #5546d7;
            --shadow: 0 12px 32px rgba(32, 43, 76, .07);
            --due-bg: #fff2de;
            --due-ink: #9c6010;
        }
        :root[data-theme="dark"] {
            color-scheme: dark;
            --page: #111522;
            --surface: #1a2030;
            --ink: #eff2ff;
            --muted: #a4acc2;
            --line: #30384c;
            --accent: #a99dff;
            --shadow: 0 12px 32px rgba(0, 0, 0, .2);
            --due-bg: #3a2c19;
            --due-ink: #ffd28b;
        }
        * { box-sizing: border-box; }
        body { margin: 0; background: var(--page); color: var(--ink); font: 15px/1.5 "Segoe UI", system-ui, sans-serif; }
        a { color: inherit; text-decoration: none; }
        button { font: inherit; }
        .layout { display: grid; grid-template-columns: 230px minmax(0, 1fr); min-height: 100vh; }
        aside { padding: 28px 18px; border-right: 1px solid var(--line); background: var(--surface); }
        .brand { display: flex; align-items: center; gap: 10px; margin: 0 0 38px 8px; font-size: 19px; font-weight: 800; letter-spacing: -.04em; }
        .brand-mark { display: grid; width: 34px; height: 34px; place-items: center; border-radius: 11px; background: #5546d7; color: white; }
        .nav-label { margin: 24px 10px 8px; color: var(--muted); font-size: 11px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
        nav a { display: flex; gap: 12px; align-items: center; margin: 4px 0; padding: 10px 12px; border-radius: 9px; color: var(--muted); font-weight: 600; }
        nav a.active { background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent); }
        .side-note { margin-top: 40px; padding: 14px; border: 1px solid var(--line); border-radius: 12px; color: var(--muted); font-size: 13px; }
        .side-note strong { display: block; margin-bottom: 4px; color: var(--ink); }
        main { width: min(1200px, 100%); margin: 0 auto; padding: 28px clamp(18px, 4vw, 48px) 56px; }
        .topbar { display: flex; justify-content: space-between; align-items: center; gap: 18px; margin-bottom: 34px; }
        .search { width: min(360px, 48vw); padding: 11px 14px; border: 1px solid var(--line); border-radius: 10px; background: var(--surface); color: var(--muted); }
        .user { display: flex; align-items: center; gap: 11px; font-weight: 700; }
        .avatar { display: grid; width: 38px; height: 38px; place-items: center; border-radius: 50%; background: #f1e7ff; color: #6944a5; font-weight: 800; }
        .welcome { margin-bottom: 24px; }
        .welcome h1 { margin: 0; font-size: clamp(26px, 3vw, 34px); letter-spacing: -.04em; }
        .welcome p { margin: 5px 0 0; color: var(--muted); }
        .stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 34px; }
        .stat { min-height: 110px; padding: 18px; border: 1px solid var(--line); border-radius: 14px; background: var(--surface); box-shadow: var(--shadow); }
        .stat-label { color: var(--muted); font-size: 13px; font-weight: 600; }
        .stat-value { display: block; margin-top: 6px; font-size: 27px; font-weight: 800; letter-spacing: -.04em; }
        .stat-note { color: var(--muted); font-size: 12px; }
        .section-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin: 0 0 14px; }
        .section-head h2 { margin: 0; font-size: 19px; letter-spacing: -.02em; }
        .section-head a { color: var(--accent); font-size: 13px; font-weight: 700; }
        .courses { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
        .course { overflow: hidden; border: 1px solid var(--line); border-radius: 15px; background: var(--surface); box-shadow: var(--shadow); }
        .course-banner { min-height: 116px; padding: 17px; color: white; }
        .course-banner.indigo { background: linear-gradient(130deg, #5752cc, #8979ee); }
        .course-banner.teal { background: linear-gradient(130deg, #087e83, #4bc6b1); }
        .course-banner.orange { background: linear-gradient(130deg, #be5e31, #f1a34b); }
        .course-banner.rose { background: linear-gradient(130deg, #a23d66, #e27e9b); }
        .course-code { display: inline-block; padding: 4px 8px; border: 1px solid rgba(255,255,255,.35); border-radius: 20px; background: rgba(255,255,255,.13); font-size: 11px; font-weight: 700; }
        .course-banner h3 { margin: 17px 0 0; font-size: 19px; letter-spacing: -.02em; }
        .course-body { padding: 15px 17px 17px; }
        .instructor { color: var(--muted); font-size: 13px; }
        .progress-label { display: flex; justify-content: space-between; margin: 17px 0 7px; color: var(--muted); font-size: 12px; }
        .progress { height: 7px; overflow: hidden; border-radius: 9px; background: var(--line); }
        .progress span { display: block; height: 100%; border-radius: inherit; background: var(--accent); }
        .course-meta { display: flex; justify-content: space-between; gap: 8px; margin-top: 13px; color: var(--muted); font-size: 12px; }
        .lower { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(260px, .85fr); gap: 20px; margin-top: 34px; }
        .panel { padding: 18px; border: 1px solid var(--line); border-radius: 14px; background: var(--surface); box-shadow: var(--shadow); }
        .assignment, .event { display: flex; justify-content: space-between; gap: 14px; padding: 14px 0; border-top: 1px solid var(--line); }
        .assignment:first-of-type, .event:first-of-type { border-top: 0; }
        .assignment strong, .event strong { display: block; font-size: 13px; }
        .assignment small, .event small { color: var(--muted); }
        .due { flex: none; height: fit-content; padding: 4px 8px; border-radius: 20px; background: var(--due-bg); color: var(--due-ink); font-size: 11px; font-weight: 700; }
        .event-icon { flex: none; display: grid; width: 34px; height: 34px; place-items: center; border-radius: 10px; background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent); }
        .theme-toggle { padding: 8px 11px; border: 1px solid var(--line); border-radius: 9px; background: var(--surface); color: var(--ink); cursor: pointer; font-size: 13px; font-weight: 700; }
        .theme-toggle:hover { border-color: var(--accent); }
        @media (max-width: 900px) { .layout { grid-template-columns: 190px minmax(0, 1fr); } .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); } .courses { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        @media (max-width: 650px) { .layout { display: block; } aside { padding: 16px 18px; border-right: 0; border-bottom: 1px solid var(--line); } .brand { margin: 0 0 12px 4px; } nav { display: flex; gap: 5px; overflow-x: auto; } nav a { flex: none; } .nav-label, .side-note { display: none; } main { padding-top: 20px; } .lower { grid-template-columns: 1fr; } }
        @media (max-width: 450px) { .stats, .courses { grid-template-columns: 1fr; } .topbar { align-items: flex-start; } .search { width: 50%; } .user-name { display: none; } }
    </style>
</head>
<body>
<div class="layout">
    <aside>
        <a class="brand" href="/" aria-label="GradeGenius home"><span class="brand-mark">G</span> GradeGenius</a>
        <nav aria-label="Main navigation">
            <a class="active" href="#overview"><span>▦</span> Overview</a>
            <a href="#courses"><span>▤</span> My courses</a>
            <a href="#assignments"><span>✓</span> Assignments</a>
            <a href="#activity"><span>◷</span> Calendar</a>
        </nav>
        <p class="nav-label">Account</p>
        <nav aria-label="Account navigation">
            <a href="#profile"><span>⚙</span> Settings</a>
        </nav>
        <div class="side-note"><strong>Keep it up, <?= $e($student['first_name']) ?>!</strong>Your weekly learning streak is <?= $e($student['streak']) ?> days.</div>
    </aside>
    <main id="overview">
        <header class="topbar">
            <div class="search" aria-label="Search courses">⌕ &nbsp; Search your courses</div>
            <div class="user">
                <button class="theme-toggle" type="button" data-theme-toggle aria-label="Switch color theme">Dark mode</button>
                <span class="avatar" aria-hidden="true"><?= $e($student['initials']) ?></span>
                <span class="user-name"><?= $e($student['name']) ?></span>
            </div>
        </header>
        <section class="welcome">
            <h1>Good afternoon, <?= $e($student['first_name']) ?> <span aria-hidden="true">👋</span></h1>
            <p>Here’s your learning overview for <?= $e($student['term']) ?>.</p>
        </section>
        <section class="stats" aria-label="Learning summary">
            <article class="stat"><span class="stat-label">Enrolled courses</span><strong class="stat-value"><?= count($courses) ?></strong><span class="stat-note">This semester</span></article>
            <article class="stat"><span class="stat-label">Average grade</span><strong class="stat-value"><?= $e($student['average']) ?></strong><span class="stat-note">Across all courses</span></article>
            <article class="stat"><span class="stat-label">Completed lessons</span><strong class="stat-value"><?= $e($student['lessons_completed']) ?></strong><span class="stat-note">Keep up the momentum</span></article>
            <article class="stat"><span class="stat-label">Due this week</span><strong class="stat-value"><?= count($assignments) ?></strong><span class="stat-note">Plan time to finish</span></article>
        </section>
        <section id="courses">
            <div class="section-head"><h2>Your courses</h2><a href="#courses">View all courses →</a></div>
            <div class="courses">
                <?php foreach ($courses as $course): ?>
                    <article class="course">
                        <div class="course-banner <?= $e($course['color']) ?>">
                            <span class="course-code"><?= $e($course['code']) ?></span>
                            <h3><?= $e($course['title']) ?></h3>
                        </div>
                        <div class="course-body">
                            <div class="instructor">Instructor · <?= $e($course['instructor']) ?></div>
                            <div class="progress-label"><span>Course progress</span><strong><?= (int) $course['progress'] ?>%</strong></div>
                            <div class="progress" role="progressbar" aria-label="<?= $e($course['title']) ?> progress" aria-valuenow="<?= (int) $course['progress'] ?>" aria-valuemin="0" aria-valuemax="100">
                                <span style="width: <?= (int) $course['progress'] ?>%"></span>
                            </div>
                            <div class="course-meta"><span><?= (int) $course['lessons_done'] ?>/<?= (int) $course['lessons_total'] ?> lessons</span><span>Grade <?= $e($course['grade']) ?></span></div>
                        </div>
                    </article>
                <?php endforeach; ?>
            </div>
        </section>
        <div class="lower">
            <section class="panel" id="assignments">
                <div class="section-head"><h2>Upcoming assignments</h2><a href="#assignments">See schedule →</a></div>
                <?php foreach ($assignments as $assignment): ?>
                    <div class="assignment">
                        <div><strong><?= $e($assignment['title']) ?></strong><small><?= $e($assignment['course']) ?> · <?= $e($assignment['type']) ?></small></div>
                        <span class="due"><?= $e($assignment['due']) ?></span>
                    </div>
                <?php endforeach; ?>
            </section>
            <section class="panel" id="activity">
                <div class="section-head"><h2>Recent activity</h2><a href="#activity">View calendar →</a></div>
                <?php foreach ($activity as $item): ?>
                    <div class="event">
                        <span class="event-icon" aria-hidden="true"><?= $e($item['icon']) ?></span>
                        <div><strong><?= $e($item['title']) ?></strong><small><?= $e($item['description']) ?> · <?= $e($item['when']) ?></small></div>
                    </div>
                <?php endforeach; ?>
            </section>
        </div>
    </main>
</div>
<script src="theme.js" defer></script>
</body>
</html>
