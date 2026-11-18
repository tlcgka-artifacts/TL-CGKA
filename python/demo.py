"""Run key updates across core and ordinary membership changes."""
from tlcgka.tl import Group
from tlcgka.membership import Membership


def show(label, driver):
    group = driver.group
    clients = (*group.cores.values(), *group.ordinary.values())
    keys = {client.key for client in clients}
    assert len(keys) == 1 and None not in keys
    assert not any(driver.queues.values())
    print(f'{label}: members={len(clients)}, cores={len(group.cores)}, '
          f'epoch={clients[0].epoch}, agreement=PASS, pending_sources=0')


def main():
    driver = Membership(Group.balanced(16, 2, 2))
    driver.update()
    show('Initial', driver)
    driver.change(0, 'A', 16)
    driver.drain()
    for _ in range(3):
        driver.update()
    show('After core 16 joins and sources rotate', driver)
    driver.change(0, 'R', 1)
    driver.drain()
    for _ in range(3):
        driver.update()
    show('After core 1 leaves and sources rotate', driver)
    for op, label in [('A', 'joins'), ('R', 'leaves')]:
        driver.change_ordinary(0, op, 17)
        driver.drain()
        driver.update()
        show(f'After ordinary member 17 {label}', driver)


if __name__ == '__main__':
    main()
